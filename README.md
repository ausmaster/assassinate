[![Assassinate Logo](./docs/Assassinate.webp)](https://github.com/ausmaster/assassinate)

[![Python Version](https://img.shields.io/badge/python-3.8+-FF8400)](https://www.python.org)
[![License](https://img.shields.io/badge/license-GPLv3-FF8400.svg)](https://github.com/ausmaster/assassinate/blob/main/LICENSE)
[![Tests](https://github.com/ausmaster/assassinate/actions/workflows/tests.yml/badge.svg?branch=main)](https://github.com/ausmaster/assassinate/actions?query=workflow%3A"tests")
[![Codecov](https://codecov.io/gh/ausmaster/assassinate/branch/main/graph/badge.svg?token=TOKEN)](https://codecov.io/gh/ausmaster/assassinate)
[![Discord](https://img.shields.io/discord/859164869970362439)](https://discord.com/invite/PZqkgxu5SA)

---

## 📚 **Overview**

**Assassinate** is a Python interface designed to interact with the **Metasploit Core shared library**. It provides both **synchronous** and **asynchronous** APIs for seamless integration with **Metasploit functionalities**, allowing for structured exploitation and automation workflows.

This project also supports **BBOT integration**, enhancing automation capabilities in larger network security operations.

---

## 🛠️ **Key Features**

- **Synchronous and Asynchronous APIs:** Effortlessly switch between blocking and non-blocking interfaces.
- **Error Handling:** Robust exception management with clear error messages.
- **JSON Support:** Easy JSON validation and parsing.
- **Logging:** Configurable logging for better debugging and monitoring.
- **BBOT Integration:** Custom configurations for smooth interaction with BBOT workflows.

---

## 📂 **Directory Structure**

```plaintext
assassinate/
├── metasploit_core/       # C Wrapper source and compiled shared library
│   ├── metasploit_core.c  # C wrapper source code
│   ├── metasploit_core.so # Compiled shared library
│   ├── Makefile           # Build automation script
│   └── README.md          # Documentation for the C wrapper
│
├── python/                # Python interface for the C library
│   ├── __init__.py        # Package initialization
│   ├── core.py            # Synchronous Python wrapper
│   ├── async_core.py      # Asynchronous Python wrapper
│   ├── exceptions.py      # Custom exception classes
│   ├── logger.py          # Logging setup
│   ├── utils.py           # Utility functions
│   ├── config.yaml        # Configuration for BBOT integration
│   ├── README.md          # Documentation for Python integration
│   └── tests/             # Unit and integration tests
│       ├── __init__.py
│       ├── test_core.py   # Tests for core functionality
│       ├── test_utils.py  # Tests for utility functions
│       └── test_module.py # Tests for BBOT module
│
├── bbot/                  # BBOT Module integration
│   ├── __init__.py        # BBOT module initialization
│   ├── assassinate.py     # BBOT-specific interface
│   ├── config.yaml        # BBOT parameters and configurations
│   ├── README.md          # BBOT-specific documentation
│
├── docs/                  # Documentation for the entire project
│   ├── installation.md    # Installation guide
│   ├── usage.md           # Usage instructions
│   ├── architecture.md    # Detailed architecture breakdown
│   ├── contributing.md    # Contribution guidelines
│   ├── api_reference.md   # API reference for Python wrapper
│   ├── Assassinate.webp   # Project logo
│
├── .gitignore             # Ignore unnecessary files
├── LICENSE                # GPL-3.0 License information
└── README.md              # Root documentation for the project
```

---

## 📥 **Installation**

### **Dependencies**
Ensure you have the following installed:
- Python 3.8+
- `ctypes` for Python
- Metasploit Framework
- `asyncio` for asynchronous tasks

### **Quick Setup**
```bash
# Clone the repository
git clone https://github.com/ausmaster/assassinate.git

# Navigate to the root folder
cd assassinate

# Install required dependencies
pip install -r requirements.txt
```

### **Build the Shared Library**
```bash
cd metasploit_core
make
```

---

## 📜 **License**

This project is licensed under the **GNU General Public License v3.0 (GPL-3.0)**. See the `LICENSE` file for more details.

---

## 🗨️ **Support**

- **Issues:** Report bugs or feature requests via the [GitHub Issues](https://github.com/ausmaster/assassinate/issues).  
- **Community:** Join the discussion on [Discord](https://discord.com/invite/PZqkgxu5SA).