from pathlib import Path

def read_lines(path):
    """Yield raw log lines from a file, stripping trailing newlines."""
    p = Path(path)
    if not p.exists():
        raise FileNotFoundError(f"Log source not found: {path}")
    with p.open("r", errors="replace") as f:
        for line in f:
            line = line.rstrip("\n")
            if line.strip():
                yield line
