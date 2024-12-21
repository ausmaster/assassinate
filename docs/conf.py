import os
import sys

# Add Python sources to the path
sys.path.insert(0, os.path.abspath("../assassinate"))

# Project Information
project = "Assassinate"
author = "Austin Stark"
release = "0.0.1"

# General Configuration
extensions = [
    "sphinx.ext.autodoc",
    "sphinx.ext.napoleon",
    "sphinx.ext.viewcode",
    "sphinx.ext.todo",
    "myst_parser",  # Enable Markdown support
]

# File formats
source_suffix = {
    ".rst": "restructuredtext",
    ".md": "markdown",
}

# HTML Output
html_theme = "alabaster"
html_static_path = ["_static"]

# Ensure _static exists
if not os.path.exists(os.path.join(os.path.dirname(__file__), "_static")):
    os.makedirs(os.path.join(os.path.dirname(__file__), "_static"))
