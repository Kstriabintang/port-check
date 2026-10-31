"""Reading and normalizing the proxy list, plus case-insensitive file lookup."""
import os

from . import config


def find_file(name):
    """Return the real path of `name`, matching case-insensitively.

    Lets the scanner run on both macOS (case-insensitive FS) and Linux
    (case-sensitive) regardless of how the file is capitalized.
    """
    if os.path.exists(name):
        return name
    folder = os.path.dirname(name) or "."
    target = os.path.basename(name).lower()
    try:
        for entry in os.listdir(folder):
            if entry.lower() == target:
                return os.path.join(folder, entry) if folder != "." else entry
    except OSError:
        pass
    return None


def _normalize(line):
    """Turn one raw line into (host, port) or None if invalid.

    Accepts: `ip:port`, `scheme://ip:port`, `scheme://user:pass@host:port`.
    """
    line = line.split("#", 1)[0].strip().strip("'\" ,")
    if not line:
        return None
    if "://" in line:
        line = line.split("://", 1)[1]
    line = line.split("@")[-1].strip("/")
    host, _, port = line.rpartition(":")
    if not host or not port.isdigit() or not 1 <= int(port) <= 65535:
        return None
    return host, int(port)


def read_proxies(argv_targets=None):
    """Read proxies from CLI args (if given) or the proxy file.

    Returns (proxies, skipped_count). `proxies` is a de-duplicated list of
    (host, port) tuples preserving first-seen order.
    """
    if argv_targets:
        lines = list(argv_targets)
    else:
        path = find_file(config.PROXY_FILE)
        if not path:
            raise FileNotFoundError(
                f"{config.PROXY_FILE} not found. Create it with one proxy per line (ip:port)."
            )
        with open(path) as f:
            lines = f.read().splitlines()

    proxies, seen, skipped = [], set(), 0
    for line in lines:
        parsed = _normalize(line)
        if parsed is None:
            if line.strip() and not line.strip().startswith("#"):
                skipped += 1
            continue
        if parsed not in seen:
            seen.add(parsed)
            proxies.append(parsed)
    return proxies, skipped


def raise_file_limit():
    """macOS caps open files at 256; raise it so hundreds of parallel sockets are safe."""
    try:
        import resource
        soft, hard = resource.getrlimit(resource.RLIMIT_NOFILE)
        target = 4096 if hard == resource.RLIM_INFINITY else min(4096, hard)
        if soft < target:
            resource.setrlimit(resource.RLIMIT_NOFILE, (target, hard))
    except Exception:
        pass
