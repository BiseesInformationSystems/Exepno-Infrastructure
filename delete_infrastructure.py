from os.path import abspath
from argparse import ArgumentParser
from pulumi.automation import create_or_select_stack, fully_qualified_stack_name, LocalWorkspaceOptions, ProjectSettings, ConfigValue

# Build Parser
parser = ArgumentParser(description="Exepno Infrastructure Deletion Tool")
parser.add_argument("name", help="[Required] Name for this deployment [Ex: dev]", metavar="NAME")
parser.add_argument("--project-id", help="[Required] GCP Project ID", required=True)
parser.add_argument("--sa-file", help="[Required] Path to GCP Service Account JSON Key file", required=True)
args = parser.parse_args()

print("Initializing Stack...")
stack_name = fully_qualified_stack_name("bisees", args.project_id, args.name)
stack = create_or_select_stack(
  stack_name, 
  project_name=args.project_id,
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

stack.set_config("gcp:project", ConfigValue(value=args.project_id))
stack.set_config("gcp:credentials", ConfigValue(value=abspath(args.sa_file), secret=True))

print("\nDeleting Exepno Infrastructure...")
res = stack.destroy()
print("Result:", res.summary.result)
exit(0)
