#!/usr/bin/env python3
"""
Evrmore Accounts Setup Script
"""

from setuptools import setup, find_packages

with open("README.md", "r", encoding="utf-8") as fh:
    long_description = fh.read()

setup(
    name="evrmore-accounts",
    version="1.0.0",
    description="A RESTful API service for Evrmore blockchain-based authentication",
    long_description=long_description,
    long_description_content_type="text/markdown",
    author="Manticore Technologies",
    author_email="dev@manticore.technology",
    url="https://github.com/manticoretechnologies/evrmore-accounts",
    packages=find_packages(),
    include_package_data=True,
    python_requires=">=3.8",
    install_requires=[
        "flask>=2.0.0",
        "flask-cors>=3.0.0",
        "flask-jwt-extended>=4.4.0",
        "pyotp>=2.8.0",
        "python-dotenv>=0.19.0",
    ],
    extras_require={
        "dev": [
            "pytest>=7.0.0",
            "flake8>=6.0.0",
            "black>=23.1.0",
            "gunicorn>=20.1.0",
            "gevent>=22.10.2",
        ],
    },
    classifiers=[
        "Development Status :: 4 - Beta",
        "Intended Audience :: Developers",
        "License :: OSI Approved :: MIT License",
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.8",
        "Programming Language :: Python :: 3.9",
        "Programming Language :: Python :: 3.10",
    ],
    entry_points={
        "console_scripts": [
            "evrmore-accounts=evrmore_accounts.app:main",
            "evrmore-healthcheck=evrmore_accounts.healthcheck:main",
        ],
    },
) 