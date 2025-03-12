#!/bin/bash
# Script to publish Evrmore Accounts to PyPI

# Clean up previous builds
rm -rf build/ dist/ *.egg-info/

# Build the package
python3 setup.py sdist bdist_wheel

# Check the package
twine check dist/*

# Upload to PyPI (uncomment when ready)
# twine upload dist/*

echo "Package built successfully. To upload to PyPI, run:"
echo "twine upload dist/*" 