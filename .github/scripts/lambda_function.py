import os
import json
import re
import time
import yaml
import jwt
import requests
import boto3
from botocore.exceptions import ClientError
import base64
import logging

logger = logging.getLogger()
logger.setLevel(logging.INFO)

DRY_RUN = os.environ.get("DRY_RUN", "false").lower() != "false"
GITHUB_API = "https://api.github.com"

def get_secret(secret_name, region_name=None):
    if not region_name:
        session = boto3.session.Session()
        region_name = session.region_name  # e.g., eu-central-1
    client = boto3.client("secretsmanager", region_name=region_name)
    try:
        resp = client.get_secret_value(SecretId=secret_name)
        return json.loads(resp["SecretString"])
    except ClientError as e:
        raise Exception(f"Unable to retrieve secret {secret_name}: {e}")

def generate_jwt(app_id, private_key):
    now = int(time.time())
    payload = {"iat": now, "exp": now + 600, "iss": app_id}
    return jwt.encode(payload, private_key, algorithm="RS256")

def get_installation_token(app_jwt, owner, repo):
    headers = {"Authorization": f"Bearer {app_jwt}", "Accept": "application/vnd.github+json"}
    r = requests.get(f"{GITHUB_API}/repos/{owner}/{repo}/installation", headers=headers)
    r.raise_for_status()
    installation_id = r.json()["id"]
    r = requests.post(f"{GITHUB_API}/app/installations/{installation_id}/access_tokens", headers=headers)
    r.raise_for_status()
    return r.json()["token"]

def fetch_file_from_github(owner, repo, path, ref, token):
    """Fetch a file from GitHub repo at a specific commit/branch"""
    url = f"{GITHUB_API}/repos/{owner}/{repo}/contents/{path}?ref={ref}"
    headers = {"Authorization": f"Bearer {token}", "Accept": "application/vnd.github+json"}
    r = requests.get(url, headers=headers)
    if r.status_code == 404:
        logger.warning(f"File {path} not found in repo {owner}/{repo} at {ref}")
        return []
    r.raise_for_status()
    content = r.json()["content"]
    return base64.b64decode(content).decode("utf-8").splitlines()

def glob_to_regex(glob_pattern):
    regex = re.escape(glob_pattern)
    regex = regex.replace(r"\*\*/", "(.*/)?").replace(r"\*\*", ".*").replace(r"\*", "[^/]*")
    regex = re.sub(r"\\\{([^}]+)\\\}", lambda m: "(" + m.group(1).replace(",", "|") + ")", regex)
    return "^" + regex + "$"

def is_excluded(file, patterns):
    for pat in patterns:
        try:
            if re.search(glob_to_regex(pat), file):
                return True
        except re.error:
            if pat in file:
                return True
    return False

def filter_files_by_region(files, region_code, regions_yaml):
    if not region_code or not regions_yaml:
        return files
    allowed_patterns = regions_yaml.get(region_code, [])
    compiled_patterns = [re.compile(glob_to_regex(p)) for p in allowed_patterns]
    return [f for f in files if any(c.search(f) for c in compiled_patterns)]

def validate_files(files, filepath_regex):
    if not filepath_regex:
        return True, []
    regex = re.compile(glob_to_regex(filepath_regex))
    invalid_files = [f for f in files if not regex.search(f)]
    return len(invalid_files) == 0, invalid_files

def detect_region(files, regions_yaml):
    for region, patterns in regions_yaml.items():
        for pat in patterns:
            regex = re.compile(glob_to_regex(pat))
            if any(regex.search(f) for f in files):
                return region
    return None

def build_folders_map(files):
    return ",".join(files)

def post_check_run(token, owner, repo, commit_sha, status, conclusion, output_title, output_summary):
    url = f"{GITHUB_API}/repos/{owner}/{repo}/check-runs"
    headers = {"Authorization": f"Bearer {token}", "Accept": "application/vnd.github+json"}
    payload = {
        "name": "CR Checker",
        "head_sha": commit_sha,
        "status": status,
        "conclusion": conclusion,
        "output": {"title": output_title, "summary": output_summary}
    }
    if DRY_RUN:
        logger.info(f"DRY RUN - would post check run: {json.dumps(payload, indent=2)}")
        return
    r = requests.post(url, headers=headers, json=payload)
    r.raise_for_status()
    return r.json()

def lambda_handler(event, context):
    try:
        changed_files = event.get("changed_files", [])
        bypass_ecab = event.get("bypass_ecab", True)
        owner = event["owner"]
        repo = event["repo"]
        commit_sha = event["commit_sha"]
        secret_name = event["github_secret_name"]

        # 1️ Fetch GitHub App secrets
        secrets = get_secret(secret_name)
        app_id = secrets["app-id"]
        private_key = secrets["private_key"]  # Correct key name

        # 2️ Generate JWT and installation token
        app_jwt = generate_jwt(app_id, private_key)
        token = get_installation_token(app_jwt, owner, repo)

        # 3️ Fetch exclude.txt and regions YAML dynamically
        exclude_patterns = fetch_file_from_github(owner, repo, ".github/configs/cr_exclude_path.txt", commit_sha, token)
        regions_yaml_lines = fetch_file_from_github(owner, repo, ".github/configs/cr_regions_path.yaml", commit_sha, token)
        regions_yaml = yaml.safe_load("\n".join(regions_yaml_lines)) or {}

        # 4️ Filter changed files
        filtered_files = [f for f in changed_files if not is_excluded(f, exclude_patterns)]

        # 5️ Determine region_code
        region_code = detect_region(filtered_files, regions_yaml)

        # 6️ Set filepath_regex
        filepath_regex = "**/*.{tf,yaml}" if region_code else ""

        # 7️ Validate files
        valid, invalid_files = validate_files(filtered_files, filepath_regex)
        region_valid_files = filter_files_by_region(filtered_files, region_code, regions_yaml)

        # 8️ Determine conclusion
        if not valid:
            conclusion = "failure"
            summary = f"Files do not match filepath-regex: {invalid_files}"
        elif len(region_valid_files) != len(filtered_files):
            conclusion = "failure"
            invalid_region_files = list(set(filtered_files) - set(region_valid_files))
            summary = f"Files do not belong to region {region_code}: {invalid_region_files}"
        else:
            conclusion = "success"
            summary = f"All {len(filtered_files)} files are valid for region {region_code}"

        # 9️ Post result to GitHub Checks API
        post_check_run(token, owner, repo, commit_sha, "completed", conclusion, "CR Checker Results", summary)

        # 10️ Return structured response
        return {
            "statusCode": 200,
            "body": json.dumps({
                "region_code": region_code,
                "folders_map": build_folders_map(filtered_files),
                "filepath_regex": filepath_regex,
                "bypass_ecab": bypass_ecab,
                "conclusion": conclusion,
                "summary": summary,
                "files": filtered_files
            })
        }

    except Exception as e:
        logger.exception("Error in Lambda handler")
        return {"statusCode": 500, "body": json.dumps({"error": str(e)})}
