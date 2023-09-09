from os import name as osname
from os.path import abspath
from re import match
from json import dumps, loads
from argparse import ArgumentParser, Namespace
import pulumi_gcp as gcp
from pulumi.automation import create_or_select_stack, fully_qualified_stack_name, LocalWorkspaceOptions, ProjectSettings, ConfigValue
from pulumi import ResourceOptions, Output, ComponentResource, export
from pulumi_kubernetes import Provider
from pulumi_kubernetes.helm.v3 import Release, ReleaseArgs, RepositoryOptsArgs
from pulumi_kubernetes.core.v1 import Namespace
from pulumi_kubernetes.yaml import ConfigGroup, ConfigFile

class K8sInfraArgs:
  def __init__(self,
               static_ip: str,
               airflow_output_bucket: str,
               airflow_logs_bucket: str,
               namespace: str,
               letsencrypt_email: str
              ):
    self.static_ip = static_ip
    self.airflow_output_bucket = airflow_output_bucket
    self.airflow_logs_bucket = airflow_logs_bucket
    self.namespace = namespace
    self.letsencrypt_email = letsencrypt_email

class K8sInfra(ComponentResource):
    def __init__(self, name: str, args: K8sInfraArgs, opts: ResourceOptions = None):
      super().__init__("bisees:kubernetes:exepno", name, {}, opts)

      exepno_ns = Namespace(
        args.namespace,
        ResourceOptions(
          parent=self,
          ignore_changes=['metadata["labels"]["kubernetes.io/metadata.name"]', 'spec']
        ),
        metadata={
          "name": args.namespace,
          "labels": {
            "bisees.com/app": "exepno-infrastructure"
          }
        }
      )

      ingress = Release(
        "ingress-nginx",
        ReleaseArgs(
          name="ingress-nginx",
          namespace=args.namespace,
          chart="ingress-nginx",
          version="4.4.2",
          repository_opts=RepositoryOptsArgs(
              repo="https://kubernetes.github.io/ingress-nginx",
          ),
          values={
            "controller": {
              "service": {
                "loadBalancerIP": args.static_ip
              },
              "ingressClassResource": {
                "default": True
              },
              "lifecycle": {
                "preStop": {
                  "exec": {
                    "command": [
                      "/bin/sh",
                      "-c",
                      "sleep 5; nginx -c /etc/nginx/nginx.conf -s quit; while pgrep -x nginx; do sleep 1; done"
                    ]
                  }
                }
              },
              "terminationGracePeriodSeconds": 600,
              "metrics": {
                "enabled": True,
                "serviceMonitor": {
                  "enabled": False,
                  "namespace": args.namespace,
                  "additionalLabels": {
                    "release": "prometheus"
                  }
                }
              }
            },
            "defaultBackend": {
              "enabled": True
            }
          },
          create_namespace=True,
          dependency_update=True,
          lint=True,
          atomic=True,
          cleanup_on_fail=True
        ),
        ResourceOptions(parent=self, depends_on=[exepno_ns])
      )

      cert_manager_crds = ConfigFile(
        "cert_manager_crds",
        file="https://github.com/cert-manager/cert-manager/releases/download/v1.12.2/cert-manager.crds.yaml",
        opts=ResourceOptions(parent=self)
      )

      cert_manager = Release(
        "cert_manager",
        ReleaseArgs(
          name="cert-manager",
          namespace=args.namespace,
          chart="cert-manager",
          version="1.12.2",
          repository_opts=RepositoryOptsArgs(
              repo="https://charts.jetstack.io",
          ),
          values={
            "prometheus": {
              "servicemonitor": {
                "enabled": False,
                "namespace": args.namespace,
                "labels": {
                  "release": "prometheus"
                }
              }
            }
          },
          create_namespace=True,
          dependency_update=True,
          lint=True,
          atomic=True,
          cleanup_on_fail=True
        ),
        ResourceOptions(
          parent=self,
          depends_on=[exepno_ns, ingress, cert_manager_crds]
        )
      )

      cert_manager_clusterissuers = ConfigGroup(
        "cert_manager_clusterissuers",
        yaml=[
'''
apiVersion: cert-manager.io/v1
kind: ClusterIssuer
metadata:
  name: letsencrypt-staging
spec:
  acme:
    # The ACME server URL
    server: https://acme-staging-v02.api.letsencrypt.org/directory
    # Email address used for ACME registration
    email: {email}
    # Name of a secret used to store the ACME account private key
    privateKeySecretRef:
      name: letsencrypt-staging
    # Enable the HTTP-01 challenge provider
    solvers:
      - http01:
          ingress:
            ingressClassName: nginx
'''.format(email=args.letsencrypt_email)
,
'''
apiVersion: cert-manager.io/v1
kind: ClusterIssuer
metadata:
  name: letsencrypt-prod
spec:
  acme:
    # The ACME server URL
    server: https://acme-v02.api.letsencrypt.org/directory
    # Email address used for ACME registration
    email: {email}
    # Name of a secret used to store the ACME account private key
    privateKeySecretRef:
      name: letsencrypt-prod
    # Enable the HTTP-01 challenge provider
    solvers:
      - http01:
          ingress:
            ingressClassName: nginx
'''.format(email=args.letsencrypt_email)
        ],
        opts=ResourceOptions(
          parent=self,
          depends_on=[cert_manager]
        )
      )

def create_infrastructure(args: Namespace):
  # Set GCP Zone
  gcp_zone = f'{args.region}-a'

  # Enable the required APIs
  enable_compute = gcp.projects.Service(
    "compute",
    service="compute.googleapis.com",
    project=args.project_id
  )

  enable_artifactregistry = gcp.projects.Service(
    "artifactregistry",
    service="artifactregistry.googleapis.com",
    project=args.project_id
  )

  enable_dns = gcp.projects.Service(
    "dns",
    service="dns.googleapis.com",
    project=args.project_id
  )

  enable_cloudresourcemanager = gcp.projects.Service(
    "cloudresourcemanager",
    service="cloudresourcemanager.googleapis.com",
    project=args.project_id
  )

  enable_storage_component = gcp.projects.Service(
    "storage_component",
    service="storage-component.googleapis.com",
    project=args.project_id
  )

  enable_storage = gcp.projects.Service(
    "storage",
    service="storage.googleapis.com",
    project=args.project_id
  )

  enable_containerregistry = gcp.projects.Service(
    "containerregistry",
    service="containerregistry.googleapis.com",
    project=args.project_id
  )

  enable_container = gcp.projects.Service(
    "container",
    service="container.googleapis.com",
    project=args.project_id
  )

  # Create a new network
  gke_network = gcp.compute.Network(
    f'{args.cluster_name}-vpc',
    name=f'{args.cluster_name}-vpc',
    auto_create_subnetworks=False,
    description="A virtual network for our GKE cluster",
    opts=ResourceOptions(
      depends_on=[
        enable_compute,
        enable_artifactregistry,
        enable_dns,
        enable_cloudresourcemanager,
        enable_storage_component,
        enable_storage,
        enable_containerregistry,
        enable_container
      ]
    )
  )

  # Create a subnet in the new network
  gke_subnet = gcp.compute.Subnetwork(
    f'{args.cluster_name}-subnet',
    name=f'{args.cluster_name}-subnet',
    ip_cidr_range="10.128.0.0/12",
    network=gke_network.id,
    private_ip_google_access=True,
    region=args.region
  )

  # Master CIDR block
  master_ipv4_cidr_block = '10.100.0.0/28'

  # Get latest GKE version
  gke_version = gcp.container.get_engine_versions(
    location=gcp_zone
  )

  # Create a cluster in the new network and subnet
  gke_cluster = gcp.container.Cluster(
    args.cluster_name,
    name=args.cluster_name,
    description="A GKE cluster for exepno-store microservices.",
    project=args.project_id,
    network=gke_network.name,
    subnetwork=gke_subnet.name,
    location=gcp_zone,
    initial_node_count=1,
    remove_default_node_pool=True,
    min_master_version=gke_version.release_channel_latest_version["STABLE"],
    ip_allocation_policy=gcp.container.ClusterIpAllocationPolicyArgs(
      cluster_ipv4_cidr_block="/14",
      services_ipv4_cidr_block="/20"
    ),
    master_authorized_networks_config=gcp.container.ClusterMasterAuthorizedNetworksConfigArgs(
      cidr_blocks=[gcp.container.ClusterMasterAuthorizedNetworksConfigCidrBlockArgs(
        cidr_block="0.0.0.0/0",
        display_name="All networks"
      )]
    ),
    networking_mode="VPC_NATIVE",
    private_cluster_config=gcp.container.ClusterPrivateClusterConfigArgs(
      enable_private_nodes=True,
      enable_private_endpoint=False,
      master_ipv4_cidr_block=master_ipv4_cidr_block
    ),
    cluster_autoscaling=gcp.container.ClusterClusterAutoscalingArgs(
      enabled=False
    ),
    addons_config=gcp.container.ClusterAddonsConfigArgs(
      dns_cache_config=gcp.container.ClusterAddonsConfigDnsCacheConfigArgs(
        enabled=True
      ),
      http_load_balancing=gcp.container.ClusterAddonsConfigHttpLoadBalancingArgs(
        disabled=True
      ),
      gce_persistent_disk_csi_driver_config=gcp.container.ClusterAddonsConfigGcePersistentDiskCsiDriverConfigArgs(
        enabled=True
      )
    ),
    monitoring_config=gcp.container.ClusterMonitoringConfigArgs(
      managed_prometheus=gcp.container.ClusterMonitoringConfigManagedPrometheusArgs(
        enabled=False
      )
    ),
    release_channel=gcp.container.ClusterReleaseChannelArgs(
      channel="STABLE"
    ),
    workload_identity_config=gcp.container.ClusterWorkloadIdentityConfigArgs(
      workload_pool=f"{args.project_id}.svc.id.goog"
    ),
    network_policy=gcp.container.ClusterNetworkPolicyArgs(
      enabled=False
    ),
    datapath_provider="ADVANCED_DATAPATH",
    opts=ResourceOptions(
      depends_on=[gke_network, gke_subnet]
    )
  )

  # Create a GCP service account for the nodepool
  gke_nodepool_sa = gcp.serviceaccount.Account(
    f'{args.cluster_name}-np-sa',
    account_id=Output.concat(gke_cluster.name, "-np-sa"),
    display_name=f'{args.cluster_name} Nodepool Service Account'
  )

  # Necessary roles for the node pool
  roles = [
    "roles/logging.logWriter",
    "roles/monitoring.metricWriter",
    "roles/monitoring.viewer",
    "roles/stackdriver.resourceMetadata.writer",
    "roles/storage.objectViewer",
    "roles/artifactregistry.reader"
  ]

  # Attach necesssary roles to the service account
  for role in roles:
    gke_nodepool_sa_permissions = gcp.projects.IAMMember(
      f'np-sa-role-{role.split("/")[1]}',
      project=args.project_id,
      role=role,
      member=gke_nodepool_sa.email.apply(lambda email: f"serviceAccount:{email}"),
      opts=ResourceOptions(
        depends_on=[gke_nodepool_sa]
      )
    )

  # Create a nodepool for the cluster
  gke_nodepool = gcp.container.NodePool(
    f'{args.cluster_name}-nodepool',
    name=f'{args.cluster_name}-nodepool',
    project=args.project_id,
    location=gcp_zone,
    cluster=gke_cluster.id,
    node_count=args.node_count,
    version=gke_version.release_channel_latest_version["STABLE"],
    management=gcp.container.NodePoolManagementArgs(
        auto_repair=True,
        auto_upgrade=True
    ),
    node_config=gcp.container.NodePoolNodeConfigArgs(
      oauth_scopes=[
        "https://www.googleapis.com/auth/logging.write",
        "https://www.googleapis.com/auth/monitoring",
        "https://www.googleapis.com/auth/devstorage.read_only",
        "https://www.googleapis.com/auth/cloud-platform",
        "https://www.googleapis.com/auth/trace.append",
        "https://www.googleapis.com/auth/service.management.readonly",
        "https://www.googleapis.com/auth/servicecontrol"
      ],
      service_account=gke_nodepool_sa.email,
      machine_type=args.machine_type,
      disk_size_gb=100,
      disk_type="pd-standard",
      image_type="COS_CONTAINERD",
      tags=[f'{args.cluster_name}-nodepool']
    ),
    opts=ResourceOptions(
      depends_on=[gke_cluster, gke_nodepool_sa]
    )
  )

  if osname == "posix":
    exe_type = ""
  else:
    exe_type = ".exe"

  # Build a Kubeconfig to access the cluster
  cluster_kubeconfig = Output.all(
    gke_cluster.master_auth.cluster_ca_certificate,
    gke_cluster.endpoint,
    gke_cluster.name,
    exe_type).apply(lambda l:
    f"""
apiVersion: v1
clusters:
- cluster:
    certificate-authority-data: {l[0]}
    server: https://{l[1]}
  name: {l[2]}
contexts:
- context:
    cluster: {l[2]}
    user: {l[2]}
  name: {l[2]}
current-context: {l[2]}
kind: Config
preferences: {{}}
users:
- name: {l[2]}
  user:
    exec:
      apiVersion: client.authentication.k8s.io/v1beta1
      command: gke-gcloud-auth-plugin{l[3]}
      installHint: Install gke-gcloud-auth-plugin for use with kubectl by following
        https://cloud.google.com/blog/products/containers-kubernetes/kubectl-auth-changes-in-gke
      interactiveMode: IfAvailable
      provideClusterInfo: true
"""
  )

  # GCP Bucket for Airflow Dags Output
  crawl_output_bucket = gcp.storage.Bucket(
    "airflowOutputBucket",
    name=f"exepno-infrastructure-airflow-output-{args.project_id}-{args.name}",
    location=args.region,
    storage_class="STANDARD"
  )

  # GCP Bucket for Airflow Logs Output
  airflow_logs_bucket = gcp.storage.Bucket(
    "airflowLogsBucket",
    name=f"exepno-infrastructure-airflow-logs-{args.project_id}-{args.name}",
    location=args.region,
    storage_class="STANDARD"
  )

  # Static IP Address for Ingress Nginx Controller
  static = gcp.compute.Address(
    "ingressStaticIP",
    name="exepno-infrastructure-ingress-nginx-controller",
    region=args.region
  )

  # Set up CloudDNS Managed Zone
  if args.setup_dns:
    dns_zone = gcp.dns.ManagedZone(
      f'{args.project_id}-{args.domain.replace(".", "-")}',
      description=f"Managed DNS Zone for {args.domain}",
      dns_name=f"{args.domain}.",
      name=args.domain.replace(".", "-")
    )

    domains = [
      "Grafana",
      "Jenkins",
      "ArgoCD",
      "Airflow",
      "Open-Metadata",
      "Kibana",
      "Jira",
      "Confluence",
      "Git",
      "Kubeshark"
    ]

    record_sets = []
    for subdomain in domains:
      record_sets.append(gcp.dns.RecordSet(
        f"{subdomain}.{args.domain}.",
        name=f"{subdomain.lower()}.{args.domain}.",
        managed_zone=dns_zone.name,
        type="A",
        ttl=60,
        rrdatas=[static.address]))

  # Create CloudNAT configuration to allow internet access to worker nodes
  router = gcp.compute.Router(
    f'{args.cluster_name}-router',
    name=f'{args.cluster_name}-router',
    description=f"Router for GKE cluster {args.cluster_name}",
    region=gke_subnet.region,
    network=gke_network.id,
    bgp=gcp.compute.RouterBgpArgs(
        asn=64514,
    ),
    opts=ResourceOptions(
      depends_on=[gke_cluster, gke_nodepool]
    )
  )

  nat = gcp.compute.RouterNat(
    f'{args.cluster_name}-nat',
    name=f'{args.cluster_name}-nat',
    region=router.region,
    router=router.name,
    nat_ip_allocate_option="AUTO_ONLY",
    source_subnetwork_ip_ranges_to_nat="LIST_OF_SUBNETWORKS",
    subnetworks=[gcp.compute.RouterNatSubnetworkArgs(
      name=gke_subnet.id,
      source_ip_ranges_to_nats=["ALL_IP_RANGES"],
    )],
    opts=ResourceOptions(
      depends_on=[gke_cluster, gke_nodepool, router]
    )
  )

  # Create Firewall Rule for the Ingress Controller
  ingress_rule = gcp.compute.Firewall(
    "ingressFirewallRule",
    name='exepno-infrastructure-ingress-nginx-webhook',
    description="Firewall rule to allow port 8443 of Ingress Nginx Webhook controller",
    network=gke_network.id,
    direction="INGRESS",
    allows=[gcp.compute.FirewallAllowArgs(
      ports=["8443"],
      protocol="tcp"
    )],
    target_tags=[f'{args.cluster_name}-nodepool'],
    source_ranges=['10.100.0.0/28'],
    opts=ResourceOptions(
      depends_on=[gke_cluster, gke_nodepool]
    )
  )

  # Configure the Kubernetes provider using the kubeconfig data
  k8s_provider = Provider(
    "bisees",
    kubeconfig=cluster_kubeconfig,
    opts=ResourceOptions(
      depends_on=[gke_cluster, gke_nodepool, router, nat]
    )
  )

  # Create all the required Kubernetes deployments
  k8s_infra = K8sInfra(
    "bisees_k8s_infra",
    args=K8sInfraArgs(
      static_ip=static.address,
      airflow_output_bucket=crawl_output_bucket.name,
      airflow_logs_bucket=airflow_logs_bucket.name,
      namespace=args.namespace,
      letsencrypt_email=args.letsencrypt_email
    ),
    opts=ResourceOptions(
      depends_on=[gke_cluster, gke_nodepool],
      providers={'kubernetes': k8s_provider}
    )
  )

  # Workload Identity configuration for Airflow
  # Create a GCP service account for Airflow
  airflow_sa = gcp.serviceaccount.Account(
    "airflow_sa",
    account_id="exepno-infrastructure-airflow",
    display_name=f'GCP SA bound to K8s SA openmetadata/airflow',
    opts=ResourceOptions(
      depends_on=[k8s_infra]
    )
  )

  # Necessary roles for Airflow
  airflow_roles = [
    "roles/bigquery.admin",
    "roles/cloudsql.admin",
    "roles/storage.admin",
    "roles/storage.objectAdmin"
  ]

  # Attach necesssary roles to the Airflow service account
  for role in airflow_roles:
    airflow_sa_permissions = gcp.projects.IAMMember(
      f'exepno-infrastructure-airflow-role-{role.split("/")[1]}',
      project=args.project_id,
      role=role,
      member=airflow_sa.email.apply(lambda email: f"serviceAccount:{email}"),
      opts=ResourceOptions(
        depends_on=[k8s_infra, airflow_sa]
      )
    )

  # Give k8s SA access to GCP Airflow SA
  k8s_sa_in_gcp_form = f'serviceAccount:{args.project_id}.svc.id.goog[{args.namespace}/airflow]'
  workload_id = gcp.serviceaccount.IAMMember(
    "workload_id_airflow_sa",
    role="roles/iam.workloadIdentityUser",
    member=k8s_sa_in_gcp_form,
    service_account_id=airflow_sa.name,
    opts=ResourceOptions(
      depends_on=[k8s_infra, airflow_sa]
    )
  )

  export("GKE Cluster Name", gke_cluster.name)
  export("Airflow Output Bucket Name", crawl_output_bucket.name)
  export("Airflow Logs Bucket Name", airflow_logs_bucket.name)
  export("Ingress Controller Public IP", static.address)
  export("Airflow ServiceAccount Email", airflow_sa.email)
  if args.setup_dns:
    for subdomain in domains:
      full_domain = f"{subdomain.lower()}.{args.domain}"
      export(f"{subdomain} Domain", full_domain)

def main():
  # Build Parser
  global_parser = ArgumentParser(description="Exepno Infrastructure Deployment Tool")
  subparsers = global_parser.add_subparsers(title="Commands", description="Create/Delete Exepno Infrastructure", required=True, metavar="ACTION")

  # Command to create the infrastructure
  up = subparsers.add_parser(name="create", help="Create Exepno Infrastructure", description="Creates a private GKE Cluster and its associated resources and installs Ingress-Nginx Controller and Cert-Manager in it.")
  up.add_argument("name", help="[Required] Name for this deployment [Ex: dev]", metavar="NAME")
  up.add_argument("--project-id", help="[Required] GCP Project ID", required=True)
  up.add_argument("--sa-file", help="[Required] Path to GCP Service Account JSON Key file", required=True)
  up.add_argument("--letsencrypt-email", help="Email address to use with Let's Encrypt Cert Manager", default="info@bisees.com")
  up.add_argument("--region", help="Region in which the Kubernetes cluster will be deployed [Default: us-central1]", default="us-central1")
  up.add_argument("--cluster-name", help="GKE Kubernetes Cluster name [Default: exepno-infrastructure]", default="exepno-infrastructure")
  up.add_argument("--node-count", help="Number of worker nodes in the Kubernetes cluster [Default: 7]", type=int, default=7)
  up.add_argument("--machine-type", help="Machine type of Kubernetes cluster worker nodes [Default: e2-standard-4]", default="e2-standard-4")
  up.add_argument("--namespace", help="Namespace in which to deploy kubernetes resources [Default: exepno-infra]", default="exepno-infra")
  up.set_defaults(func="create", setup_dns=False, domain=None)

  # Command to delete the infrastructure
  down = subparsers.add_parser(name="delete", help="Delete Exepno Infrastructure", description="Deletes the private GKE Cluster and its associated resources.")
  down.add_argument("name", help="[Required] Name for this deployment [Ex: dev]", metavar="NAME")
  down.add_argument("--project-id", help="[Required] GCP Project ID", required=True)
  down.add_argument("--sa-file", help="[Required] Path to GCP Service Account JSON Key file", required=True)
  down.add_argument("--cluster-name", help="[Required] GKE Kubernetes Cluster name", required=True)
  down.add_argument("--region", help="GKE Kubernetes Cluster region [Default: us-central1]", default="us-central1")
  down.set_defaults(func="delete")

  args = global_parser.parse_args()

  print("Initializing Stack...")
  stack_name = fully_qualified_stack_name("bisees", args.project_id, args.name)
  stack = create_or_select_stack(
    stack_name, 
    project_name=args.project_id,
    program=lambda: create_infrastructure(args),
    opts=LocalWorkspaceOptions(
      env_vars={
        "PULUMI_ACCESS_TOKEN": "pul-deacb40d41cb450344bcc9f80aa5faba782e7f16"
      },
      project_settings=ProjectSettings(
        name=args.project_id,
        runtime="python",
        description="Python program to deploy a Kubernetes cluster on Google Cloud to be used by the Cloud Marketplace K8s Application.",
        author="Adnan Saifee <asaifee02@gmail.com>"
      )
    )
  )
  print("Successfully initialized the stack.")

  print("Installing plugins...")
  stack.workspace.install_plugin("gcp", "v6.64.0")
  stack.workspace.install_plugin("kubernetes", "v4.1.1")
  print("Successfully installed the required plugins.\n")

  # Ask whether to create CloudDNS Zone
  dns_answer = input("Do you want to create a CloudDNS Managed Zone for your Domain? [yes/no]: ")
  if dns_answer == "yes":
    args.setup_dns = True
    found = False
    while not found:
      domain = input("Enter your domain name: ")
      matched = match('^([a-z0-9]+(-[a-z0-9]+)*\.)+[a-z]{2,}$', domain)
      if matched:
        args.domain = matched.string
        found = True
      else:
        domain = None
        print("Incorrect value for domain. Please try again.")
  else:
    print("Skipping DNS Automation.")

  stack.set_config("gcp:project", ConfigValue(value=args.project_id))
  stack.set_config("gcp:region", ConfigValue(value=args.region))
  stack.set_config("gcp:zone", ConfigValue(value=f"{args.region}-a"))
  stack.set_config("gcp:credentials", ConfigValue(value=abspath(args.sa_file), secret=True))

  if args.func == "create":
    print("\nCreating Exepno Infrastructure...")
    res = stack.up()
    print("Result:", res.summary.result)
    res_json = loads(f'{res.outputs}'.replace('\'', '\"'))
    print("Outputs:")
    for k, v in res_json.items():
      print(f'\t{k:<30}: {v:<10}')

  elif args.func == "delete":
    print("\nDeleting Exepno Infrastructure...")
    res = stack.destroy()
    print("Result:", res.summary.result)
    exit(0)

  else:
    print("\nIncorrect command.")
    exit(1)

if __name__ == "__main__":
  main()
