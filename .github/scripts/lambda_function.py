import os
import re
import subprocess
import json
import fnmatch

def run(cmd):
    result = subprocess.run(
        cmd, shell=True, text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE
    )
    return result.stdout.strip()


def load_filelist():
    base = run("git merge-base origin/main HEAD")
    files = run(f"git diff --name-only --diff-filter=ACMRT {base} HEAD")
    return files.split() if files else []

def file_matches_any(file, patterns):
    for pat in patterns:
        if fnmatch.fnmatch(file, pat):
            return True
    return False

def exclude_by_patterns(file, exclude_patterns):
    for pat in exclude_patterns:
        if re.search(pat, file):
            return True
    return False

def convert_glob_to_regex(glob):
    regex = glob
    regex = regex.replace(".", r"\.")          # escape dots
    regex = regex.replace("**/", "(.*/)?")     # double-star folder prefix
    regex = regex.replace("**", ".*")          # remaining **
    regex = regex.replace("*", "[^/]*")        # single star
    regex = re.sub(r"\{([^}]+)\}", r"(\1)", regex)  # extensions list
    return "^" + regex + "$"

def validate_chg(files):
    allowed = [
        "**/*.tf",
        "**/*.yaml",
        "**/*.sh",
        "**/*.ps1",
        "**/*.psm1",
        "**/*.json",
        "**/*.yml"
    ]

    disallowed = []

    allowed_regex = [re.compile(convert_glob_to_regex(g)) for g in allowed]

    for f in files:
        if not any(r.match(f) for r in allowed_regex):
            disallowed.append(f)

    return disallowed

def match_region(file, suffix):
    pattern = f".*{re.escape(suffix)}.*"
    return re.search(pattern, file) is not None


def detect_region(files):
    if any(match_region(f, "/stage/") for f in files):
        return "stage"
    if any(match_region(f, "/dev/") for f in files):
        return "dev"
    return "main"

def build_folder_map(files):
    s = " ".join(files)
    s = " ".join(s.split())  # collapse multiple spaces
    items = s.split(" ") if s else []
    return ",".join(items)

def load_exclude_patterns(path="exclude.txt"):
    if not os.path.exists(path):
        return []
    with open(path) as f:
        return [line.strip() for line in f if line.strip()]

def lambda_handler(event, context):
    # 1. Changed files
    changed = load_filelist()

    # 2. Exclude files
    excludes = load_exclude_patterns("exclude.txt")
    filtered = [f for f in changed if not exclude_by_patterns(f, excludes)]

    # 3. validate-chg
    disallowed = validate_chg(filtered)
    if disallowed:
        return {
            "statusCode": 400,
            "body": json.dumps({
                "error": "Illegal file types modified",
                "files": disallowed
            })
        }

    # 4. Detect region
    region = detect_region(filtered)

    # 5. Build folder map
    folder_map = build_folder_map(filtered)

    return {
        "statusCode": 200,
        "body": json.dumps({
            "region": region,
            "folder_map": folder_map,
            "files": filtered
        })
    }
