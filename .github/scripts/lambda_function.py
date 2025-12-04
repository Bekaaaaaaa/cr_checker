import os
import json
import re
import time
import yaml
import jwt
import requests
from pathlib import Path
from fnmatch import fnmatch
import boto3
from botocore.exceptions import ClientError

DRY_RUN = os.environ.get("DRY_RUN", "false").lower() != "false"
GITHUB_API = "https://api.github.com"

def get_secret(secret_name, region_name=None):
    if not region_name:
        region_name = os.environ.get("AWS_REGION", "us-east-1")
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

def load_exclude_patterns(exclude_file=".github/configs/cr_exclude_path.txt"):
    path = Path(exclude_file)
    if not path.exists():
        return []
    with path.open() as f:
        return [line.strip() for line in f if line.strip()]

def is_excluded(file, patterns):
    for pat in patterns:
        try:
            if re.search(pat, file):
                return True
        except re.error:
            if pat in file:
                return True
    return False

def load_regions(yaml_file=".github/configs/cr_regions_path.yaml"):
    path = Path(yaml_file)
    if not path.exists():
        return {}
    with path.open() as f:
        data = yaml.safe_load(f) or {}
    return data

def glob_to_regex(glob_pattern):
    regex = glob_pattern
    regex = regex.replace(".", r"\.")
    regex = regex.replace("**/", "(.*/)?")
    regex = regex.replace("**", ".*")
    regex = regex.replace("*", "[^/]*")
    regex = re.sub(r"\{([^}]+)\}", r"(\1)", regex)
    return "^" + regex + "$"

def filter_files_by_region(files, region_code, regions_yaml):
    if not region_code or not regions_yaml:
        return files
    allowed_patterns = regions_yaml.get(region_code, [])
    compiled_patterns = [re.compile(glob_to_regex(p)) for p in allowed_patterns]
    valid_files = []
    for f in files:
        if any(c.search(f) for c in compiled_patterns):
            valid_files.append(f)
    return valid_files

def validate_files(files, filepath_regex):
    if not filepath_regex:
        return True, []
    regex = re.compile(glob_to_regex(filepath_regex))
    invalid_files = [f for f in files if not regex.search(f)]
    return len(invalid_files) == 0, invalid_files

def build_folders_map(files):
    return ",".join(files)

def detect_region(files, regions_yaml):
    for region, patterns in regions_yaml.items():
        for pat in patterns:
            regex = re.compile(glob_to_regex(pat))
            if any(regex.search(f) for f in files):
                return region
    return ""

def post_check_run(token, owner, repo, commit_sha, status, conclusion, output_title, output_summary):
    url = f"{GITHUB_API}/repos/{owner}/{repo}/check-runs"
    headers = {
        "Authorization": f"Bearer {token}",
        "Accept": "application/vnd.github+json"
    }
    payload = {
        "name": "CR Checker",
        "head_sha": commit_sha,
        "status": status,
        "conclusion": conclusion,
        "output": {
            "title": output_title,
            "summary": output_summary
        }
    }
    if DRY_RUN:
        print(f"DRY RUN - would post check run: {json.dumps(payload, indent=2)}")
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
        private_key = secrets["client-secret"]

        # 2️ Generate JWT and installation token
        app_jwt = generate_jwt(app_id, private_key)
        token = get_installation_token(app_jwt, owner, repo)

        # 3️ Filter changed files
        exclude_patterns = load_exclude_patterns()
        filtered_files = [f for f in changed_files if not is_excluded(f, exclude_patterns)]

        # 4️ Determine region_code
        regions_yaml = load_regions()
        region_code = detect_region(filtered_files, regions_yaml)

        # 5️ Set filepath_regex
        filepath_regex = "**/*.{tf,yaml}" if region_code else ""

        # 6️ Validate files
        valid, invalid_files = validate_files(filtered_files, filepath_regex)
        region_valid_files = filter_files_by_region(filtered_files, region_code, regions_yaml)

        # 7️ Determine conclusion
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

        # 8️ Post result to GitHub Checks API
        post_check_run(
            token,
            owner,
            repo,
            commit_sha,
            status="completed",
            conclusion=conclusion,
            output_title="CR Checker Results",
            output_summary=summary
        )

        # 9️ Return structured response
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
        return {"statusCode": 500, "body": json.dumps({"error": str(e)})}
