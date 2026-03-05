from importlib.metadata import version, PackageNotFoundError
from log import NOTICE
from synoacl import Acl, Ace, check_synoacltool
import argparse
import fcntl
import logging
import os
import re
import sys
import tomllib
import yaml

LOCK_FILE_NAME = ".ensure-project-acl.lock"
EXCLUDED_DIRS = {"@eaDir", "#recycle", "#snapshot"}

logging.basicConfig(
    datefmt="%Y-%m-%d %H:%M:%S",
    format='%(asctime)s [%(levelname)s] %(message)s',
    level=NOTICE,
)
logger = logging.getLogger(__name__)

def get_version():
    try:
        return version("ensure-project-acl")
    except PackageNotFoundError:
        try:
            pyproject = os.path.join(os.path.dirname(__file__), "pyproject.toml")
            with open(pyproject, "rb") as f:
                return tomllib.load(f)["project"]["version"]
        except Exception:
            return "unknown"

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
            elif isinstance(pattern, str):
                try:
                    re.compile(pattern)
                except re.error as e:
                    errors.append(f"{rule_prefix}: invalid regex pattern '{pattern}': {e}")
            elif isinstance(pattern, list):
                for k, p in enumerate(pattern, 1):
                    if not isinstance(p, str):
                        errors.append(f"{rule_prefix}.pattern[{k}]: must be a string")
                    else:
                        try:
                            re.compile(p)
                        except re.error as e:
                            errors.append(f"{rule_prefix}.pattern[{k}]: invalid regex '{p}': {e}")
            else:
                errors.append(f"{rule_prefix}: 'pattern' must be a string or list of strings")
            pattern_mode = rule.get("pattern_mode", "any")
            if pattern_mode not in ("any", "all"):
                errors.append(f"{rule_prefix}: 'pattern_mode' must be 'any' or 'all'")
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
            if result.is_symlink() or not result.is_dir() or result.name in EXCLUDED_DIRS:
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

def pattern_matches(pattern, pattern_mode, name):
    """Check if name matches pattern(s). Returns True if matched."""
    if isinstance(pattern, str):
        return bool(re.search(pattern, name, re.IGNORECASE))
    patterns = pattern
    if pattern_mode == "all":
        return all(re.search(p, name, re.IGNORECASE) for p in patterns)
    return any(re.search(p, name, re.IGNORECASE) for p in patterns)

def apply_rules_to_path(path, name, rules, stats):
    """Apply rules to a single path, return count of rule matches."""
    matches = 0
    for rule in rules:
        pattern = rule.get("pattern")
        pattern_mode = rule.get("pattern_mode", "any")
        logger.debug(f"pattern: {pattern} (mode: {pattern_mode})")
        config = rule.get("ensure_acl")
        if not pattern or not config:
            continue
        if pattern_matches(pattern, pattern_mode, name):
            rule_name = rule.get('name', 'unknown')
            logger.debug(f"[rule \"{rule_name}\"] matches on: {name}")
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
                            stats["rules_applied"] += 1
                        else:
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

def acquire_lock(root_path):
    """Acquire exclusive lock, returns (file_handle, lock_path) or (None, None)."""
    lock_path = os.path.join(root_path, LOCK_FILE_NAME)
    lock_file = None
    try:
        lock_file = open(lock_path, 'w')
        fcntl.flock(lock_file, fcntl.LOCK_EX | fcntl.LOCK_NB)
        lock_file.write(f"{os.getpid()}\n")
        lock_file.flush()
        logger.debug(f"acquired lock: {lock_path}")
        return lock_file, lock_path
    except BlockingIOError:
        logger.error(f"another instance is already running (lock file: {lock_path})")
        if lock_file:
            lock_file.close()
        return None, None
    except OSError as e:
        logger.error(f"failed to acquire lock at {lock_path}: {e}")
        if lock_file:
            lock_file.close()
        return None, None

def release_lock(lock_file, lock_path):
    """Delete lock file, release lock, and close handle."""
    if not lock_file:
        return
    try:
        os.unlink(lock_path)
        logger.debug(f"removed lock file: {lock_path}")
    except OSError as e:
        logger.warning(f"failed to remove lock file {lock_path}: {e}")
    try:
        fcntl.flock(lock_file, fcntl.LOCK_UN)
        lock_file.close()
    except Exception as e:
        logger.warning(f"error releasing lock: {e}")

def run_policy(policy_path, root):
    """Main processing logic, called after lock is acquired."""
    if not check_synoacltool():
        return 1
    policy = parse_policy(policy_path)
    if not policy:
        logger.error(f"aborting due to policy validation fail")
        return 1
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
        logger.info(f"scanning {root} for marker: {marker_name}")
        projects_found = 0
        for dirpath, dirnames, filenames in os.walk(root, followlinks=False, onerror=lambda e: logger.warning(f"cannot access directory: {e}")):
            dirnames[:] = [d for d in dirnames if d not in EXCLUDED_DIRS]
            if marker_name in filenames:
                projects_found += 1
                stats["projects_found"] += 1
                try:
                    logger.info(f"processing project: {dirpath}")
                    process_project(dirpath, schema.get("rules", []), stats)
                except Exception as e:
                    logger.error(f"failed to process project at {dirpath}: {type(e).__name__}: {e}")
                    stats["projects_failed"] += 1
        if projects_found == 0:
            logger.warning(f"0 projects found with marker '{marker_name}' in root {root}")
        else:
            logger.info(f"found {projects_found} projects with marker: {marker_name}")
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

def main():
    if sys.argv[1:] == ["--version"] or sys.argv[1:] == ["-v"]:
        print(get_version())
        return 1
    parser = argparse.ArgumentParser(description="sets ACLs on desired directories according to a policy file (yaml)")
    parser.add_argument("--policy", required=True, help="Path to policy.yaml")
    parser.add_argument("--root", required=True, help="Root directory (e.g. /volume1/PROJECTS)")
    parser.add_argument("--debug", action="store_true", help="Enable debug logging")
    args = parser.parse_args()
    if args.debug:
        logging.getLogger().setLevel(logging.DEBUG)
    if not os.path.isdir(args.root):
        logger.error(f"search root is not a directory: {args.root}")
        return 1
    lock_file, lock_path = acquire_lock(args.root)
    if not lock_file:
        return 1
    try:
        return run_policy(args.policy, args.root)
    finally:
        release_lock(lock_file, lock_path)

if __name__ == '__main__':
    exit(main())