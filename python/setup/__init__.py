"""Assassinate Setup - Automated Installation and Configuration.

This package provides a unified, cross-platform installation system using
Ansible Runner. It handles all dependencies for Assassinate and Metasploit
Framework across multiple Linux distributions.

Supported Distributions:
    - Ubuntu/Debian (apt)
    - Fedora/RHEL/CentOS (dnf)
    - Arch Linux (pacman)
    - openSUSE (zypper)
    - macOS (brew)
    - Kali Linux (package MSF)
    - Parrot OS (package MSF)

Installation Components:
    1. System Packages - Build tools, libraries, and dependencies
    2. Rust Toolchain - rustc, cargo via rustup or system packages
    3. Rust Build - ipc, bridge, daemon components
    4. Ruby Environment - Ruby, bundler, gem configuration
    5. Metasploit Framework - Package install or git clone with bundler

Usage (CLI):
    # Full installation (recommended)
    assassinate-setup --install

    # Selective installation
    assassinate-setup --install --steps packages,rust,build
    assassinate-setup --install --skip-steps msf

    # Verification and status
    assassinate-setup --verify
    assassinate-setup --recon-only

    # Force reinstallation
    assassinate-setup --install --force

    # Verbose output
    assassinate-setup --install -v

Usage (Programmatic):
    from setup.installer import Installer, Step

    # Full installation
    installer = Installer()
    installer.install()

    # Selective installation
    installer = Installer(steps={Step.PACKAGES, Step.RUST})
    installer.install()

    # Check status
    status = installer.verify()
    installer.print_status()

Step-based Architecture:
    The installer uses an enum-based step system for extensibility:
    - Step.PACKAGES: System package installation
    - Step.RUST: Rust toolchain setup
    - Step.BUILD: Rust component compilation
    - Step.RUBY: Ruby/Bundler configuration
    - Step.MSF: Metasploit Framework setup

Modules:
    installer: Core installation logic with Ansible Runner
    cli: Command-line interface and user interaction
"""

__all__ = ["installer", "cli"]
