import sys
from pathlib import Path

# Allow importing base/ modules by their bare names (e.g. "import Protocol")
sys.path.insert(0, str(Path(__file__).parent.parent / "base"))
