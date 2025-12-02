import os

from assassinate.bridge import get_version, initialize


def main():
    # Priority: 1) MSF_ROOT env var, 2) Default relative path
    msf_path = os.getenv("MSF_ROOT", "../../metasploit-framework")
    print(f"Initializing Metasploit from {msf_path}...")
    initialize(msf_path)

    # Get MSF version without creating framework
    version = get_version()
    print(f"MSF Version: {version}\n")


if __name__ == "__main__":
    main()
