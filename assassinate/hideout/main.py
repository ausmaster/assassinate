from assassinate.bridge import Framework, get_version, initialize


def main():
    initialize()

    # Get MSF version without creating framework
    version = get_version()
    print(f"MSF Version: {version}\n")  # noqa: T201

    # Create framework instance
    print("Creating framework...")  # noqa: T201
    fw = Framework()
    print(f"Framework: {fw}\n")  # noqa: T201

    # List available modules
    print("Listing modules...")  # noqa: T201
    exploits = fw.list_modules("exploits")
    auxiliary = fw.list_modules("auxiliary")
    payloads = fw.list_modules("payloads")

    print(f"  Exploits:  {len(exploits)}")  # noqa: T201
    print(f"  Auxiliary: {len(auxiliary)}")  # noqa: T201
    print(f"  Payloads:  {len(payloads)}\n")  # noqa: T201

    # Show first 5 exploits
    print("Sample exploits:")  # noqa: T201
    for exploit in exploits[:5]:
        print(f"  - {exploit}")  # noqa: T201
    print()  # noqa: T201


if __name__ == "__main__":
    main()
