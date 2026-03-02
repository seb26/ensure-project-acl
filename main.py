import logging
import os
import yaml
import re
import argparse
import subprocess
from pathlib import Path
from synoacl import Acl, Ace

logging.basicConfig(
    datefmt="%Y-%m-%d %H:%M:%S",
    format='%(asctime)s [%(levelname)s] %(message)s',
    level=logging.INFO,
)
logger = logging.getLogger(__name__)

def validate_policy(policy):
    """Validate policy structure and return list of errors."""
    errors = []
    if not isinstance(policy, dict):
        return ["policy must be a YAML mapping"]
    schemarules = policy.get("schemarules")
    if not schemarules:
        return ["policy must contain 'schemarules' list"]
    if not isinstance(schemarules, list):
        return ["'schemarules' must be a list"]
    for i, schema in enumerate(schemarules, 1):
        prefix = f"schemarule[{i}]"
        if not isinstance(schema, dict):
            errors.append(f"{prefix}: must be a mapping")
            continue
        criteria = schema.get("selection_criteria", {})
        marker_name = criteria.get("marker_file", {}).get("name")
        if not marker_name:
            errors.append(f"{prefix}: missing selection_criteria.marker_file.name")
        rules = schema.get("rules", [])
        if not isinstance(rules, list):
            errors.append(f"{prefix}: 'rules' must be a list")
            continue
        for j, rule in enumerate(rules, 1):
            rule_prefix = f"{prefix}.rule[{j}]"
            if not isinstance(rule, dict):
                errors.append(f"{rule_prefix}: must be a mapping")
                continue
            pattern = rule.get("pattern")
            if not pattern:
                errors.append(f"{rule_prefix}: missing 'pattern'")
            else:
                try:
                    re.compile(pattern)
                except re.error as e:
                    errors.append(f"{rule_prefix}: invalid regex pattern '{pattern}': {e}")
            acl_cfg = rule.get("ensure_acl")
            if not acl_cfg:
                errors.append(f"{rule_prefix}: missing 'ensure_acl'")
            elif isinstance(acl_cfg, dict):
                if not acl_cfg.get("rights"):
                    errors.append(f"{rule_prefix}: missing 'ensure_acl.rights'")
                if not acl_cfg.get("apply_to"):
                    errors.append(f"{rule_prefix}: missing 'ensure_acl.apply_to'")
                if not acl_cfg.get("objects"):
                    errors.append(f"{rule_prefix}: missing 'ensure_acl.objects'")
    return errors

def parse_policy(policy_path):
    """Load and validate policy file, returning None on failure."""
    try:
        with open(policy_path, "r") as f:
            policy = yaml.safe_load(f)
    except FileNotFoundError:
        logger.error(f"policy file not found: {policy_path}")
        return None
    except yaml.YAMLError as e:
        logger.error(f"invalid YAML in policy file {policy_path}: {e}")
        return None
    except Exception as e:
        logger.error(f"failed to load policy file {policy_path}: {e}")
        return None
    errors = validate_policy(policy)
    if errors:
        logger.error(f"policy validation failed with {len(errors)} error(s):")
        for err in errors:
            logger.error(f"  - {err}")
        return None
    return policy

def process_project(project_path, rules, stats):
    """Process ACL rules for a project, continuing on errors."""
    try:
        if not os.path.isdir(project_path):
            logger.error(f"project path is not accessible: {project_path}")
            stats["projects_failed"] += 1
            return
        matches_found = 0
        for result in os.scandir(project_path):
            if not result.is_dir() or result.name == "@eaDir":
                continue
            try:
                logger.debug(f"{result.name}: evaluating...")
                matches_found += apply_rules_to_path(result.path, result.name, rules, stats)
            except OSError as e:
                logger.error(f"cannot access {result.path}: {e}")
                stats["directories_failed"] += 1
                continue
            except Exception as e:
                logger.error(f"unexpected error processing {result.path}: {type(e).__name__}: {e}")
                stats["directories_failed"] += 1
                continue
        if matches_found > 0:
            stats["directories_matched"] += matches_found
        else:
            logger.debug(f"project {project_path}: no matching subdirectories")
    except OSError as e:
        logger.error(f"cannot scan project directory {project_path}: {e}")
        stats["directories_failed"] += 1
    except Exception as e:
        logger.error(f"unexpected error in project processing {project_path}: {type(e).__name__}: {e}")
        stats["directories_failed"] += 1

def apply_rules_to_path(path, name, rules, stats):
    """Apply rules to a single path, return count of rule matches."""
    matches = 0
    for rule in rules:
        pattern = rule.get("pattern")
        logger.debug(f"pattern: {pattern}")
        config = rule.get("ensure_acl")
        if not pattern or not config:
            continue
        if re.search(pattern, name, re.IGNORECASE):
            rule_name = rule.get('name', 'unknown')
            logger.info(f"[rule \"{rule_name}\"] matches on: {name}")
            matches += 1
            try:
                target_acl = Acl(path)
                for subject in config.get('objects', []):
                    try:
                        target_ace = Ace(
                            principal_type=config.get('principal_type', 'group'),
                            name=subject,
                            access=config.get('type', 'allow'),
                            rights=config['rights'],
                            apply_to=config['apply_to']
                        )
                        changed = target_acl.sync_ace(target_ace)
                        if changed:
                            logger.info(f"[rule \"{rule_name}\"] applied change OK to {path}")
                            stats["rules_applied"] += 1
                        else:
                            logger.debug(f"[rule \"{rule_name}\"] no change needed for {path}")
                            stats["rules_no_change_needed"] += 1
                    except Exception as e:
                        logger.error(f"[rule \"{rule_name}\"] failed to apply ACE to {path}: {type(e).__name__}: {e}")
                        stats["rules_failed"] += 1
                        continue

            except Exception as e:
                logger.error(f"[rule \"{rule_name}\"] failed to load/sync ACL for {path}: {type(e).__name__}: {e}")
                stats["rules_failed"] += 1
                continue
        else:
            logger.debug(f"[rule \"{rule.get('name')}\"] no match for pattern {pattern} on: {name}")
    return matches

def main():
    parser = argparse.ArgumentParser(description="Synology ACL Policy Enforcer")
    parser.add_argument("--policy", required=True, help="Path to policy.yaml")
    parser.add_argument("--root", required=True, help="Search root directory (e.g. /volume1/PROJECTS)")
    parser.add_argument("--debug", action="store_true", help="Enable debug logging")
    args = parser.parse_args()
    if args.debug:
        logger.setLevel(logging.DEBUG)
    if not os.path.isdir(args.root):
        logger.error(f"search root is not a directory: {args.root}")
        return
    policy = parse_policy(args.policy)
    if not policy:
        logger.error(f"aborting due to policy validation fail")
        return
    stats = {
        "projects_found": 0,
        "projects_failed": 0,
        "directories_matched": 0,
        "directories_failed": 0,
        "rules_applied": 0,
        "rules_no_change_needed": 0,
        "rules_failed": 0,
    }
    schema_count = 0
    for schema in policy.get("schemarules", []):
        schema_count += 1
        criteria = schema.get("selection_criteria", {})
        marker_cfg = criteria.get("marker_file", {})
        marker_name = marker_cfg.get("name")
        if not marker_name:
            logger.warning(f"schema rule {schema_count} has no marker_file.name, skipping")
            continue
        try:
            logger.info(f"scanning {args.root} for marker: {marker_name}")
            markers = subprocess.check_output(
                ["find", args.root, "-name", marker_name, "-type", "f"],
                text=True,
                timeout=300  # 5 minute timeout for find
            ).splitlines()
            if not markers:
                logger.info(f"no projects found with marker: {marker_name}")
                continue
            logger.info(f"found {len(markers)} projects with marker: {marker_name}")
            stats["projects_found"] += len(markers)
            for m in markers:
                try:
                    project_root = os.path.dirname(m)
                    logger.info(f"Processing project: {project_root}")
                    process_project(project_root, schema.get("rules", []), stats)
                except Exception as e:
                    logger.error(f"failed to process project at {m}: {type(e).__name__}: {e}")
                    stats["projects_failed"] += 1
                    continue
        except subprocess.TimeoutExpired:
            logger.error(f"find command timeout searching for marker {marker_name}")
            continue
        except subprocess.CalledProcessError as e:
            logger.error(f"find command failed for marker {marker_name}: {e}")
            continue
        except Exception as e:
            logger.error(f"unexpected error processing marker {marker_name}: {type(e).__name__}: {e}")
            continue
    logger.info("=" * 60)
    logger.info("Processing Summary:")
    logger.info(f"  Projects found:         {stats['projects_found']}")
    logger.info(f"  Projects failed:        {stats['projects_failed']}")
    logger.info(f"  Directories matched:    {stats['directories_matched']}")
    logger.info(f"  Directories failed:     {stats['directories_failed']}")
    logger.info(f"  Rules applied:          {stats['rules_applied']}")
    logger.info(f"  Rules no change needed: {stats['rules_no_change_needed']}")
    logger.info(f"  Rules failed:           {stats['rules_failed']}")
    logger.info("=" * 60)
    failures = stats['projects_failed'] + stats['directories_failed'] + stats['rules_failed']
    if failures > 0:
        logger.warning("some operations failed - check logs above for details")
        return 1
    return 0

if __name__ == '__main__':
    exit(main())