"""Empty, dedicated directories for the decoy process (pentest F-01, defence in depth).

The decoy's working directory and the SMB IPC$ share are backed by an empty directory under the sensor's
data dir, never by the image's working directory (/opt/rpot: the ReD-Pot source). Anything that resolves a
path relative to the CWD or to an empty share path then sees nothing.
"""
import os
import tempfile


def empty_dir(parent, name, mode=0o100):
    """Return the absolute path of an EMPTY directory `parent/name` (created if missing).

    If that path exists but is not an empty directory we own (left-over files, a symlink, a file), a fresh
    private directory is made next to it instead: we never serve, list or delete what is there. The result
    is chmod'ed to `mode` (default execute-only for the owner: it cannot even be listed)."""
    parent = os.path.abspath(parent)
    os.makedirs(parent, exist_ok=True)
    p = os.path.join(parent, name)
    try:
        if not os.path.lexists(p):
            os.mkdir(p, 0o700)
        if os.path.islink(p) or not os.path.isdir(p):
            raise OSError("not a plain directory")
        os.chmod(p, 0o700)                      # an earlier run left it execute-only: make it listable to check
        if os.listdir(p):
            raise OSError("not empty")
    except OSError:
        p = tempfile.mkdtemp(prefix=f".{name}-", dir=parent)
    os.chmod(p, mode)
    return os.path.realpath(p)


def chdir_empty(data_dir):
    """Make the process CWD an empty directory (call once at decoy start, after imports)."""
    d = empty_dir(data_dir, "cwd")
    os.chdir(d)
    return d
