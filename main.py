import logging
import os
import yaml
import re
import argparse
import subprocess
from synoacl import Acl, Ace

logging.basicConfig(format='%(asctime)s - %(levelname)s - %(message)s', level=logging.DEBUG)
logger = logging.getLogger(__name__)

def parse_policy(policy_path):
    try:
        with open(policy_path, "r") as f:
            return yaml.safe_load(f)
    except Exception as e:
        logger.error(f"Failed to load policy file {policy_path}: {e}")
        return None

def process_project(project_path, rules):
    try:
        for entry in os.scandir(project_path):
            if not entry.is_dir() or entry.name == "@eaDir":
                continue
            for rule in rules:
                pattern = rule.get("pattern")
                logger.debug(f"pattern: {pattern}")
                config = rule.get("ensure_acl")
                if not pattern or not config:
                    continue
                if re.search(pattern, entry.name, re.IGNORECASE):
                    target_acl = Acl(entry.path)
                    for subject in config['objects']:
                        target_ace = Ace(
                            principal_type=config.get('principal_type', 'group'),
                            name=subject,
                            access=config.get('type', 'allow'),
                            rights=config['rights'],
                            apply_to=config['apply_to']
                        )
                        target_acl.sync_ace(target_ace)
                else:
                    logger.info(f"no match for pattern {pattern} in entry {entry.name}")
    except OSError as e:
        logger.error(f"Could not scan project directory {project_path}: {e}")

def main():
    parser = argparse.ArgumentParser(description="Synology ACL Policy Enforcer")
    parser.add_argument("--policy", required=True, help="Path to policy.yaml")
    parser.add_argument("--root", required=True, help="Search root directory (e.g. /volume1/PROJECTS)")
    args = parser.parse_args()
    if not os.path.isdir(args.root):
        logger.error(f"Search root is not a directory: {args.root}")
        return
    policy = parse_policy(args.policy)
    if not policy:
        return
    for schema in policy.get("schemarules", []):
        criteria = schema.get("selection_criteria", {})
        marker_cfg = criteria.get("marker_file", {})
        marker_name = marker_cfg.get("name")
        if not marker_name:
            continue
        try:
            logger.info(f"xScanning {args.root} for marker: {marker_name}")
            markers = subprocess.check_output(
                ["find", args.root, "-name", marker_name], 
                text=True
            ).splitlines()
            for m in markers:
                project_root = os.path.dirname(m)
                logger.info(f"Processing project: {project_root}")
                process_project(project_root, schema.get("rules", []))
        except subprocess.CalledProcessError as e:
            logger.error(f"Find command failed in {args.root}: {e}")

if __name__ == '__main__':
    main()