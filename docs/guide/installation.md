# Installation

This guide explains how to install the Evrmore Accounts package and its dependencies.

## Prerequisites

Before installing Evrmore Accounts, ensure you have the following:

- Python 3.7 or later
- pip package manager
- (Optional) A virtual environment tool like venv or conda

## Installing from PyPI

The recommended way to install Evrmore Accounts is via pip:

```bash
pip3 install evrmore-accounts
```

This will install Evrmore Accounts and all its dependencies.

## Installing from Source

Alternatively, you can install from source:

```bash
# Clone the repository
git clone https://github.com/manticoretechnologies/evrmore-accounts.git
cd evrmore-accounts

# Install in development mode
pip3 install -e .
```

## Docker Installation

Evrmore Accounts is also available as a Docker image:

```bash
# Pull the image
docker pull manticoretechnologies/evrmore-accounts

# Run the container
docker run -p 5000:5000 manticoretechnologies/evrmore-accounts
```

## Dependencies

Evrmore Accounts relies on the following packages:

- Flask (>=2.0.0)
- Flask-CORS (>=3.0.0)
- Evrmore Authentication (>=0.3.0)
- Python-dotenv (>=0.19.0)

## Verifying Installation

To verify the installation, run:

```bash
python3 -c "import evrmore_accounts; print(evrmore_accounts.__version__)"
```

This should display the installed version of Evrmore Accounts.

## Next Steps

Once installed, check out the [Quick Start Guide](quickstart.md) to begin using Evrmore Accounts. 