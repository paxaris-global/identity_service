
import os
import subprocess
import tempfile
import requests
import argparse

def create_argocd_app(app_name, repo_url, path, namespace="argocd", dest_namespace="default"):
    # Ensure app_name is RFC 1123 compliant
    safe_app_name = app_name.replace('_', '-').lower()

    app_yaml = f"""
apiVersion: argoproj.io/v1alpha1
kind: Application
metadata:
  name: {safe_app_name}
  namespace: {namespace}
spec:
  project: default
  source:
    repoURL: '{repo_url}'
    targetRevision: main
    path: {path}
  destination:
    server: 'https://kubernetes.default.svc'
    namespace: {dest_namespace}
  syncPolicy:
    automated:
      prune: true
      selfHeal: true
    syncOptions:
      - CreateNamespace=true
"""

    yaml_file = os.path.join(tempfile.gettempdir(), f"{safe_app_name}-argocd-app.yaml")

    with open(yaml_file, "w") as f:
        f.write(app_yaml)

    try:
        subprocess.run(["kubectl", "apply", "-f", yaml_file], check=True)
        print(f"ArgoCD Application '{safe_app_name}' created/updated successfully.")
    except subprocess.CalledProcessError as e:
        print(f"Error applying ArgoCD Application for {safe_app_name}: {e}")
    finally:
        if os.path.exists(yaml_file):
            os.remove(yaml_file)


def fetch_org_repos(org, token):
    headers = {"Authorization": f"token {token}"}
    repos = []
    url = f"https://api.github.com/orgs/{org}/repos?per_page=100"

    while url:
        resp = requests.get(url, headers=headers)
        if resp.status_code != 200:
            print(f"Failed to fetch org repos for {org}: {resp.text}")
            return []

        repos.extend(resp.json())
        url = resp.links['next']['url'] if 'next' in resp.links else None

    return repos


def fetch_personal_repos(token):
    headers = {"Authorization": f"token {token}"}
    repos = []
    url = "https://api.github.com/user/repos?per_page=100"

    while url:
        resp = requests.get(url, headers=headers)
        if resp.status_code != 200:
            print(f"Failed to fetch personal repos: {resp.text}")
            return []

        repos.extend(resp.json())
        url = resp.links['next']['url'] if 'next' in resp.links else None

    return repos

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Register ArgoCD Applications for all repos in a GitHub org or a single repo.")
    parser.add_argument("--org", help="GitHub organization name (e.g., PaxarisGlobal)")
    parser.add_argument("--token", help="GitHub personal access token (or set GITHUB_TOKEN env var)")
    parser.add_argument("--path", required=True, help="Path in the repo to Kubernetes manifests (e.g., 'k8' or 'paxo/k8')")
    parser.add_argument("--namespace", default="argocd", help="ArgoCD namespace (default: argocd)")
    parser.add_argument("--dest-namespace", default="default", help="Destination namespace in cluster (default: default)")
    parser.add_argument("--single", action="store_true", help="Register a single repo (use legacy args)")
    parser.add_argument("--app-name", help="Name of the ArgoCD Application (for single mode)")
    parser.add_argument("--repo-url", help="GitHub repository URL (for single mode)")
    args = parser.parse_args()

    if args.single:
        if not args.app_name or not args.repo_url:
            print("--app-name and --repo-url are required in --single mode")
        else:
            create_argocd_app(
                app_name=args.app_name,
                repo_url=args.repo_url,
                path=args.path,
                namespace=args.namespace,
                dest_namespace=args.dest_namespace
            )
    else:
        token = args.token or os.environ.get("GITHUB_TOKEN")
        if not args.org or not token:
            print("--org and --token (or GITHUB_TOKEN env var) are required for org mode")
        else:
            register_all_org_repos(
                org=args.org,
                token=token,
                path=args.path,
                namespace=args.namespace,
                dest_namespace=args.dest_namespace
            )