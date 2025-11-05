import os
import re
import subprocess
import yaml
from pathlib import Path
from fnmatch import fnmatch

# ----------------------------
# Helper Functions
# ----------------------------
def run_command(cmd):
    """Run shell command and return output."""
    result = subprocess.run(cmd, shell=True, text=True, capture_output=True)
    result.check_returncode()
    return result.stdout.strip()

def get_base_branch():
    """Detect the base branch (default 'main') from environment or git)."""
    base = os.environ.get("BASE_BRANCH", "main")
    print(f"Using base branch: {base}")
    return base

def get_changed_files(base_branch=None, include_globs=None):
    """
    Detect all changed files compared to base_branch (like tj-actions/changed-files).
    include_globs: list of glob patterns to filter files (like 'releases/**').
    """
    if base_branch is None:
        base_branch = get_base_branch()

    print(f"Fetching changed files compared to {base_branch}...")

    # Ensure we have the latest from origin
    run_command(f"git fetch origin {base_branch}")

    # Get the merge base between HEAD and base_branch
    merge_base = run_command(f"git merge-base HEAD origin/{base_branch}")
    print(f"Merge base commit: {merge_base}")

    # Get all changed files since the merge base
    changed = run_command(f"git diff --name-only {merge_base} HEAD")
    changed_files = [f for f in changed.splitlines() if f.strip()]

    # Apply include globs if provided
    if include_globs:
        filtered = []
        for f in changed_files:
            if any(fnmatch(f, pattern) for pattern in include_globs):
                filtered.append(f)
        changed_files = filtered

    print(f"Detected {len(changed_files)} changed files: {changed_files}")
    return changed_files

def filter_excluded_files(files, exclude_file=".github/configs/cr_exclude_path.txt"):
    """Filter files using regex patterns in exclude.txt"""
    exclude_path = Path(exclude_file)
    if not exclude_path.exists() or exclude_path.stat().st_size == 0:
        print("No exclude.txt found or file is empty.")
        return files

    with open(exclude_path) as f:
        patterns = [line.strip() for line in f if line.strip()]

    filtered_files = []
    for file in files:
        if any(re.search(pattern, file) for pattern in patterns):
            print(f"Skipping excluded file: {file}")
        else:
            filtered_files.append(file)

    print(f"Filtered files: {filtered_files}")
    return filtered_files

def get_region_code(filtered_files, yaml_file='.github/configs/cr_regions_path.yaml'):
    """Determine region_code by reading cr_regions_path.yaml"""
    if not filtered_files:
        return ""

    yaml_path = Path(yaml_file)
    if not yaml_path.exists():
        print(f"YAML file {yaml_file} not found. Skipping region_code.")
        return ""

    with open(yaml_path) as f:
        regions_data = yaml.safe_load(f)

    # Match files to region patterns
    for region, paths in regions_data.items():
        for path_pattern in paths:
            regex = re.compile(path_pattern.replace("**", ".*"))
            if any(regex.match(f) for f in filtered_files):
                print(f"Region matched: {region}")
                return region

    print("No region matched.")
    return ""

# ----------------------------
# Validate-CHG Implementation
# ----------------------------
def validate_chg(region_code, filepath_regex, folders_map, yaml_file='.github/configs/cr_regions_path.yaml', bypass_ecab=True):
    """Fully emulate validate-chg step."""
    print("\n=== Running validate-chg ===")
    if not folders_map:
        print("No files to validate. Skipping.")
        return

    files = folders_map.split(",")
    print(f"Validating {len(files)} files for region '{region_code}'...")

    # Step 1: Check filepath_regex
    if filepath_regex:
        regex_pattern = filepath_regex.replace("**", ".*").replace("{tf,yaml}", "(tf|yaml)$")
        pattern = re.compile(regex_pattern)
        invalid_files = [f for f in files if not pattern.search(f)]
        if invalid_files:
            print(f"Error: Files do not match filepath-regex '{filepath_regex}':")
            for f in invalid_files:
                print(f"  - {f}")
            raise SystemExit("validate-chg failed due to filepath regex mismatch")

    # Step 2: Check region mapping
    yaml_path = Path(yaml_file)
    if yaml_path.exists():
        with open(yaml_path) as f:
            regions_data = yaml.safe_load(f)
        allowed_patterns = regions_data.get(region_code, [])
        invalid_region_files = []
        for f in files:
            if not any(re.compile(p.replace("**", ".*")).match(f) for p in allowed_patterns):
                invalid_region_files.append(f)
        if invalid_region_files:
            print(f"Error: Files do not belong to region '{region_code}':")
            for f in invalid_region_files:
                print(f"  - {f}")
            raise SystemExit("validate-chg failed due to region mismatch")

    if bypass_ecab:
        print("ECAB check bypassed (bypass_ecab=True).")

    print("validate-chg passed successfully.")

# ----------------------------
# Main Workflow
# ----------------------------
def main():
    print("=== CR Checker Full Emulated Workflow ===")

    # Step 1: Get changed files (simulate tj-actions/changed-files)
    include_globs = ["releases/**"]  # same as in YAML
    changed_files = get_changed_files(include_globs=include_globs)

    # Step 2: Filter excluded files
    filtered_files = filter_excluded_files(changed_files)

    # Step 3: Folders map (comma-separated)
    folders_map = ",".join(filtered_files)
    print(f"folders_map: {folders_map}")

    # Step 4: Determine region_code
    region_code = get_region_code(filtered_files)
    print(f"region_code: {region_code}")

    # Step 5: Set filepath-regex
    filepath_regex = "**/*.{tf,yaml}" if region_code else ""
    print(f"filepath_regex: {filepath_regex}")

    # Step 6: Run validate-chg
    validate_chg(region_code, filepath_regex, folders_map)

if __name__ == "__main__":
    main()
