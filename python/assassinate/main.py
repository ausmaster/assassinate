from .hideout import Hideout


def main():
    ho = Hideout()

    # List available modules
    print("Listing modules...")  # noqa: T201
    exploits = ho.framework.list_modules("exploits")
    auxiliary = ho.framework.list_modules("auxiliary")
    payloads = ho.framework.list_modules("payloads")

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
