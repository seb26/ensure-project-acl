import os
import re
import stat
import subprocess
import shutil
import logging

logger = logging.getLogger(__name__)

def check_synoacltool():
    """Verify synoacltool is available, returns True if found."""
    if shutil.which("synoacltool") is None:
        logger.error("synoacltool not found in PATH")
        return False
    return True

SYNOLOGY_PERMISSION_BITS = {
    "r": "List folders/Read data",
    "w": "Create files/Write data",
    "x": "Traverse folders/Execute files",
    "p": "Create folders/Append data",
    "d": "Delete",
    "D": "Delete subfolders and files",
    "a": "Read attributes",
    "A": "Write attributes",
    "R": "Read extended attributes",
    "W": "Write extended attributes",
    "c": "Read permissions",
    "C": "Change permissions",
    "o": "Take ownership",
}

SYNOLOGY_INHERIT_BITS = {
    "f": "Child files",
    "d": "Child folders",
    "i": "Inherit only",
    "n": "No propagate",
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
        """Convert human-readable permission labels to synoacltool permission string."""
        mask = ""
        for bit in "rwxpdDaARWcCo":
            label = SYNOLOGY_PERMISSION_BITS.get(bit, "")
            mask += bit if label in requested else "-"
        return mask

    def _build_inherit(self, apply_to):
        """Convert human-readable inheritance labels to synoacltool inherit string."""
        if "All descendants" in apply_to:
            bits = {"f", "d"}
        else:
            label_to_bit = {label: bit for bit, label in SYNOLOGY_INHERIT_BITS.items()}
            bits = {label_to_bit[label] for label in apply_to if label in label_to_bit}
        mask = ""
        for bit in "fdin":
            mask += bit if bit in bits else "-"
        return mask

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
        self.loaded = False
        self.ace_pattern = re.compile(r"^\s*\[(\d+)\]\s+(user|group|owner|everyone|authenticated_user|system):(.+):(allow|deny):([rwxpdDaARWcCo-]+):([fdin-]+)\s+\(level:(\d+)\)")
        if not self.load():
            raise RuntimeError(f"failed to load ACL for {path}")

    def _synoacltool(self, args, check=True):
        cmd = ['synoacltool'] + args
        logger.debug(f"executing: {' '.join(cmd)}")
        try:
            result = subprocess.run(cmd, capture_output=True, text=True)
            logger.debug(f"synoacltool returned: code={result.returncode}, stdout={result.stdout.strip()!r}, stderr={result.stderr.strip()!r}")
            if check and result.returncode != 0:
                error_msg = result.stderr.strip() if result.stderr else f"exit code {result.returncode}"
                logger.error(f"synoacltool error: {error_msg} (cmd: {' '.join(cmd)})")
                return None
            return result
        except Exception as e:
            logger.error(f"unexpected synoacltool error: {type(e).__name__}: {e}")
            return None

    def load(self):
        result = self._synoacltool(['-get', self.path], check=False)
        if not result:
            logger.error(f"failed to execute synoacltool for {self.path}")
            self.loaded = False
            return False
        self.entries = []
        # Handle "no ACL" case - synoacltool returns 255 when directory has no ACL
        # It outputs "It's Linux mode" to stdout when the path uses standard POSIX perms
        if result.returncode != 0:
            stdout = result.stdout.strip()
            if result.returncode == 255 and ("Linux mode" in stdout or stdout == ""):
                logger.info(f"folder {self.path} is in Linux mode - initializing ACL with inheritance")
                # Capture POSIX mode before enforce-inherit (which may change it)
                original_posix_mode = None
                try:
                    original_posix_mode = stat.S_IMODE(os.stat(self.path).st_mode)
                    logger.debug(f"captured POSIX mode {oct(original_posix_mode)} for {self.path}")
                except OSError as e:
                    logger.warning(f"failed to capture POSIX mode for {self.path}: {e}")
                # Use enforce-inherit to initialize ACL from parent
                enforce_result = self._synoacltool(['-enforce-inherit', self.path])
                if enforce_result is None:
                    logger.error(f"failed to enforce-inherit on {self.path}")
                    self.loaded = False
                    return False
                # Restore POSIX mode if we captured it
                if original_posix_mode is not None:
                    try:
                        os.chmod(self.path, original_posix_mode)
                        logger.debug(f"restored POSIX mode {oct(original_posix_mode)} for {self.path}")
                    except OSError as e:
                        logger.warning(f"failed to restore POSIX mode for {self.path}: {e}")
                # Reload to get the inherited ACEs
                reload_result = self._synoacltool(['-get', self.path], check=False)
                if not reload_result or reload_result.returncode != 0:
                    logger.error(f"failed to reload ACL after enforce-inherit for {self.path}")
                    self.loaded = False
                    return False
                # Parse the reloaded ACL
                for line in reload_result.stdout.splitlines():
                    match = self.ace_pattern.match(line)
                    if match:
                        idx, p_type, name, access, perms, inherit, level = match.groups()
                        self.entries.append(Ace(p_type, name, access, perms, inherit, level, idx))
                logger.info(f"initialized ACL for {self.path} with {len(self.entries)} inherited entries")
                self.loaded = True
                return True
            else:
                error_msg = result.stderr.strip() if result.stderr else f"exit code {result.returncode}"
                logger.error(f"synoacltool -get failed for {self.path}: {error_msg}")
                self.loaded = False
                return False
        for line in result.stdout.splitlines():
            match = self.ace_pattern.match(line)
            if match:
                idx, p_type, name, access, perms, inherit, level = match.groups()
                self.entries.append(Ace(p_type, name, access, perms, inherit, level, idx))
            else:
                if line.strip():
                    logger.debug(f"unparseable ACL line: {line}")
        self.loaded = True
        return True

    def sync_ace(self, target_ace):
        """Sync ACE to match target. Returns True if changed, False if no change.
        Raises RuntimeError on failure."""
        all_explicit = [e for e in self.entries if e.name == target_ace.name 
                        and e.principal_type == target_ace.principal_type and e.level == 0]
        if not all_explicit:
            self._add_ace(target_ace)
            return True
        if len(all_explicit) > 1:
            # Delete redundant ACEs from highest index to lowest (indices shift after deletions)
            extras_sorted = sorted(all_explicit[1:], key=lambda e: int(e.index), reverse=True)
            for extra in extras_sorted:
                self._del_ace(extra.index)
            # Reload after deletions
            if not self.load():
                raise RuntimeError(f"failed to reload ACL after deletion for {self.path}")
            all_explicit = [e for e in self.entries if e.name == target_ace.name 
                            and e.principal_type == target_ace.principal_type and e.level == 0]
            if not all_explicit:
                logger.warning(f"ACE disappeared after cleanup, re-adding for {self.path}")
                self._add_ace(target_ace)
                return True
            # Also check if remaining ACE needs update after cleanup
            primary = all_explicit[0]
            if primary.perms != target_ace.perms or primary.inherit != target_ace.inherit or primary.access != target_ace.access:
                self._replace_ace(primary.index, target_ace)
            return True
        primary = all_explicit[0]
        if primary.perms != target_ace.perms or primary.inherit != target_ace.inherit or primary.access != target_ace.access:
            self._replace_ace(primary.index, target_ace)
            return True
        logger.debug(f"no change needed: {target_ace.principal_type}:{target_ace.name} on {self.path}")
        return False

    def _add_ace(self, target_ace) -> None:
        """Add ACE. Raises RuntimeError on failure."""
        result = self._synoacltool(['-add', self.path, target_ace.to_syno_str()])
        if result is None:
            raise RuntimeError(f"failed to add ACE to {self.path}")
        logger.info(f"added {target_ace.principal_type}:{target_ace.name} to {self.path}")
        # Update local state so subsequent sync_ace calls see this ACE
        added_ace = Ace(target_ace.principal_type, target_ace.name, target_ace.access,
                        target_ace.perms, target_ace.inherit, level=0, index=None)
        self.entries.append(added_ace)

    def _replace_ace(self, index: str, target_ace) -> None:
        """Replace ACE at index. Raises RuntimeError on failure."""
        result = self._synoacltool(['-replace', self.path, str(index), target_ace.to_syno_str()])
        if result is None:
            raise RuntimeError(f"failed to replace ACE at index {index} for {self.path}")
        logger.info(f"updated {target_ace.principal_type}:{target_ace.name} on {self.path}")

    def _del_ace(self, index: str) -> None:
        """Delete ACE at index. Raises RuntimeError on failure."""
        logger.debug(f"correction: {self.path} -> delete redundant index {index}")
        result = self._synoacltool(['-del', self.path, str(index)])
        if result is None:
            raise RuntimeError(f"failed to delete ACE at index {index} for {self.path}")