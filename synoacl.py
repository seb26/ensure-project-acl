import re
import subprocess
import logging

logger = logging.getLogger(__name__)

SYNOLOGY_UI_SCHEMA = {
    "Administration": {
        "Change permissions": "C",
        "Take ownership": "o"
    },
    "Read": {
        "Traverse folders/Execute files": "x",
        "List folders/Read data": "r",
        "Read attributes": "a",
        "Read extended attributes": "R",
        "Read permissions": "c"
    },
    "Write": {
        "Create files/Write data": "w",
        "Create folders/Append data": "p",
        "Write attributes": "A",
        "Write extended attributes": "W",
        "Delete subfolders and files": "D",
        "Delete": "d"
    }
}

SYNOLOGY_UI_INHERIT_MAP = {
    "Child files": "f",
    "Child folders": "d",
    "Inherit only": "i",
    "No propagate": "n",
    "All descendants": "fd"
}

class Ace:
    def __init__(self, principal_type, name, access, rights, apply_to, level=0, index=None):
        self.principal_type = principal_type
        self.name = name
        self.access = access
        self.level = int(level)
        self.index = index
        self.perms = rights if isinstance(rights, str) else self._build_mask(rights)
        self.inherit = apply_to if isinstance(apply_to, str) else self._build_inherit(apply_to)

    def _build_mask(self, requested):
        lookup = {label: bit for cat in SYNOLOGY_UI_SCHEMA.values() for label, bit in cat.items()}
        order = "rwxpdDaARWcCo"
        mask = ""
        for char in order:
            active_labels = [label for label, bit in lookup.items() if bit == char]
            mask += char if any(item in requested for item in active_labels) else "-"
        return mask

    def _build_inherit(self, apply_to):
        # 1. Map labels to bit characters
        s = ""
        if "All descendants" in apply_to:
            s = "fd"
        else:
            for item in apply_to:
                s += SYNOLOGY_UI_INHERIT_MAP.get(item, "")
        # 2. Normalize: Remove existing dashes, unique chars only
        chars = set(s.replace("-", ""))
        # 3. Build the 4-character string in strict Synology order: f, d, i, n
        order = "fdin"
        result = ""
        for bit in order:
            result += bit if bit in chars else "-"
        return result

    def __eq__(self, other):
        if not isinstance(other, Ace): return False
        return (self.principal_type == other.principal_type and
                self.name == other.name and self.access == other.access and
                self.perms == other.perms and self.inherit == other.inherit and
                self.level == other.level)

    def to_syno_str(self):
        return f"{self.principal_type}:{self.name}:{self.access}:{self.perms}:{self.inherit}"

class Acl:
    def __init__(self, path):
        self.path = path
        self.entries = []
        self.ace_pattern = re.compile(r"^\s*\[(\d+)\]\s+(user|group|owner|everyone|authenticated_user|system):(.+):(allow|deny):([rwxpdDaARWcCo-]+):([fdin-]+)\s+\(level:(\d+)\)")
        self.load()

    def _synoacltool(self, args):
        cmd = ['synoacltool'] + args
        logger.debug(f"executing: {' '.join(cmd)}")
        try:
            return subprocess.run(cmd, capture_output=True, text=True, check=True)
        except subprocess.CalledProcessError as e:
            error_msg = e.stderr.strip() if e.stderr else f"exit code {e.returncode}"
            logger.error(f"synoacltool error: {error_msg} (cmd: {' '.join(cmd)})")
            return None
        except Exception as e:
            logger.error(f"unexpected synoacltool error: {type(e).__name__}: {e}")
            return None

    def load(self):
        result = self._synoacltool(['-get', self.path])
        if not result:
            logger.error(f"failed to load ACL for {self.path}")
            return False
        self.entries = []
        for line in result.stdout.splitlines():
            match = self.ace_pattern.match(line)
            if match:
                idx, p_type, name, access, perms, inherit, level = match.groups()
                self.entries.append(Ace(p_type, name, access, perms, inherit, level, idx))
            else:
                # Log unexpected output lines for debugging
                if line.strip():
                    logger.debug(f"unparseable ACL line: {line}")
        return True

    def sync_ace(self, target_ace) -> bool:
        """Sync ACE, logging failures without crashing."""
        try:
            all_explicit = [e for e in self.entries if e.name == target_ace.name 
                            and e.principal_type == target_ace.principal_type and e.level == 0]
            if not all_explicit:
                return self._add_ace(target_ace)
            
            if len(all_explicit) > 1:
                for extra in all_explicit[1:]:
                    if not self._del_ace(extra.index):
                        logger.warning(f"failed to delete redundant ACE at index {extra.index} for {self.path}")
                # Reload after deletions
                if not self.load():
                    logger.warning(f"failed to reload ACL after deletion for {self.path}")
                    return False
                all_explicit = [e for e in self.entries if e.name == target_ace.name and e.level == 0]
                if not all_explicit:
                    logger.warning(f"ACE disappeared after cleanup, re-adding for {self.path}")
                    return self._add_ace(target_ace)
            
            primary = all_explicit[0]
            if primary.perms != target_ace.perms or primary.inherit != target_ace.inherit or primary.access != target_ace.access:
                return self._replace_ace(primary.index, target_ace)
            else:
                logger.debug(f"no changes needed for {self.path} -> {target_ace.to_syno_str()}")
                return False
        except Exception as e:
            logger.error(f"unexpected error syncing ACE for {self.path}: {type(e).__name__}: {e}")
            return False

    def _add_ace(self, target_ace) -> bool:
        logger.info(f"correction: {self.path} -> add {target_ace.to_syno_str()}")
        result = self._synoacltool(['-add', self.path, target_ace.to_syno_str()])
        if result is None:
            logger.error(f"failed to add ACE to {self.path}")
            return False
        return True

    def _replace_ace(self, index: str, target_ace) -> bool:
        logger.info(f"correction: {self.path} -> replace index {index} with {target_ace.to_syno_str()}")
        result = self._synoacltool(['-replace', self.path, str(index), target_ace.to_syno_str()])
        if result is None:
            logger.error(f"failed to replace ACE at index {index} for {self.path}")
            return False
        return True

    def _del_ace(self, index: str) -> bool:
        logger.info(f"correction: {self.path} -> delete redundant index {index}")
        result = self._synoacltool(['-del', self.path, str(index)])
        if result is None:
            logger.error(f"failed to delete ACE at index {index} for {self.path}")
            return False
        return True