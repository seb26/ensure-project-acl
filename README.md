# ensure-project-acl

Sets ACLs on directories according to a policy file. Designed for Synology NAS systems using synoacltool.

## Requirements

- Python 3.13+
- Synology DSM

Tested so far on DSM 7.2.2.

## Installation

```
# git clone
uv sync
```

## Usage

```
ensure-project-acl --policy POLICY --root ROOT [--debug]
```

Options:
- --policy POLICY  Path to policy.yaml
- --root ROOT      Root directory (e.g. /volume1/PROJECTS)
- --debug          Enable debug logging

## ACL policy

The policy file defines rules that match directories and apply ACLs. See policy.example.yaml for a minimal example.

Directories are selected for examination according to criteria. At the moment there is only one supported criteria:

- Presence of marker file

Rules use regex patterns to match subdirectory names and define the ACL entries to ensure.

```yaml
schemarules:
  - name: "string"
    selection_criteria:
      marker_file:
        name: "_Project.txt" # presence of this file indicates project directory and OK to examine
    rules:
      - name: "string"
        pattern: "regex pattern"
        ensure_acl:
          principal_type: "group" # user or group
          objects: ["users"] # object name
          rights:
            # default: none
            # Following Synology File Station UI order:
            # Administration
            - "Change permissions"
            - "Take ownership"
            # Read
            - "Traverse folders/Execute files"
            - "List folders/Read data"
            - "Read attributes"
            - "Read extended attributes"
            - "Read permissions"
            # Write
            - "Create files/Write data"
            - "Create folders/Append data"
            - "Write attributes"
            - "Write extended attributes"
            - "Delete subfolders and files"
            - "Delete"
          apply_to:
            # default: all are true
            this_folder: true
            child_files: true
            child_folders: true
            all_descendants: true
```