#!/usr/bin/env python3
"""
Evrmore Accounts - Setup Script

This script installs the Evrmore Accounts package.
"""
from setuptools import setup, find_packages
import os

# Load version from package
with open(os.path.join("evrmore_accounts", "__init__.py"), "r") as f:
    for line in f:
        if line.startswith("__version__"):
            version = line.split("=")[1].strip().strip('"\'')
            break
    else:
        version = "0.0.1"

# Load README for long description
with open("README.md", "r") as f:
    long_description = f.read()

setup(
    name="evrmore-accounts",
    version=version,
    description="Evrmore blockchain-based authentication REST API for web applications",
    long_description=long_description,
    long_description_content_type="text/markdown",
    author="Manticore Technologies",
    author_email="dev@manticore.technology",
    url="https://github.com/manticoretechnologies/evrmore-accounts",
    packages=find_packages(),
    include_package_data=True,
    package_data={
        "evrmore_accounts": [
            "data/*"
        ]
    },
    install_requires=[
        "flask>=2.0.0",
        "flask-cors>=3.0.0",
        "evrmore-authentication>=0.3.0",
        "python-dotenv>=0.19.0"
    ],
    classifiers=[
        "Development Status :: 4 - Beta",
        "Intended Audience :: Developers",
        "License :: OSI Approved :: MIT License",
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.7",
        "Programming Language :: Python :: 3.8",
        "Programming Language :: Python :: 3.9",
        "Programming Language :: Python :: 3.10",
        "Topic :: Software Development :: Libraries :: Python Modules",
    ],
    python_requires=">=3.7",
) 