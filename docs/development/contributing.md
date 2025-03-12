# Contributing to Evrmore Accounts

Thank you for your interest in contributing to Evrmore Accounts! This document provides guidelines and instructions for contributing to the project.

## Code of Conduct

Please be respectful and considerate of others when contributing to this project. We aim to foster an inclusive and welcoming community.

## Getting Started

1. **Fork the repository** on GitHub
2. **Clone your fork** to your local machine
3. **Create a virtual environment** and install dependencies:

```bash
# Create a virtual environment
python3 -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate

# Install dependencies
pip3 install -e ".[dev]"
```

## Development Workflow

1. **Create a branch** for your changes:

```bash
git checkout -b feature/your-feature-name
```

2. **Make your changes** and write tests if applicable
3. **Run the tests** to ensure everything works:

```bash
pytest
```

4. **Format your code** using Black and isort:

```bash
black evrmore_accounts
isort evrmore_accounts
```

5. **Commit your changes** with a descriptive commit message:

```bash
git commit -m "Add feature: your feature description"
```

6. **Push your changes** to your fork:

```bash
git push origin feature/your-feature-name
```

7. **Create a pull request** from your fork to the main repository

## Pull Request Guidelines

- Keep pull requests focused on a single feature or bug fix
- Include tests for new features or bug fixes
- Update documentation as needed
- Follow the existing code style
- Make sure all tests pass before submitting

## Code Style

We follow the [PEP 8](https://www.python.org/dev/peps/pep-0008/) style guide for Python code. We use Black and isort to automatically format code.

```bash
# Format code with Black
black evrmore_accounts

# Sort imports with isort
isort evrmore_accounts
```

## Testing

We use pytest for testing. Please write tests for new features and ensure that all tests pass before submitting a pull request.

```bash
# Run all tests
pytest

# Run tests with coverage
pytest --cov=evrmore_accounts
```

## Documentation

We use MkDocs for documentation. Please update the documentation as needed when adding or changing features.

```bash
# Install MkDocs and dependencies
pip3 install mkdocs mkdocs-material mkdocstrings

# Run the documentation server locally
mkdocs serve

# Build the documentation
mkdocs build
```

## Release Process

1. Update the version number in `evrmore_accounts/__init__.py`
2. Update the changelog in `docs/about/changelog.md`
3. Create a new release on GitHub with release notes
4. Publish to PyPI:

```bash
# Clean previous builds
rm -rf build/ dist/ *.egg-info/

# Build the package
python3 setup.py sdist bdist_wheel

# Upload to PyPI
twine upload dist/*
```

## Getting Help

If you have questions or need help, please:

1. Check the [documentation](https://manticoretechnologies.github.io/evrmore-accounts/)
2. Open an issue on GitHub
3. Contact the maintainers at [dev@manticore.technology](mailto:dev@manticore.technology)

## Thank You!

Your contributions are greatly appreciated and help make Evrmore Accounts better for everyone! 