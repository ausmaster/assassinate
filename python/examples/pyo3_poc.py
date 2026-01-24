"""Proof-of-concept for direct Pyo3/Magnus bridge usage.

Usage:
    python python/examples/pyo3_poc.py /path/to/metasploit-framework
"""

from __future__ import annotations

import sys

import assassinate_pyo3


def main() -> int:
    if len(sys.argv) != 2:
        print(
            "Usage: python python/examples/pyo3_poc.py /path/to/metasploit-framework"
        )
        return 1

    msf_root = sys.argv[1]
    try:
        assassinate_pyo3.init_msf(msf_root)
        version = assassinate_pyo3.framework_version()
    except assassinate_pyo3.AssassinateError as exc:
        print(f"Failed to initialize MSF: {exc}")
        return 1

    print(f"MSF Version: {version}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
