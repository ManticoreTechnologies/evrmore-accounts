#!/bin/bash
# Script to deploy Evrmore Accounts documentation to GitHub Pages

# Install MkDocs and required plugins if not already installed
pip3 install mkdocs mkdocs-material mkdocstrings

# Build the documentation
mkdocs build

# Deploy to GitHub Pages
mkdocs gh-deploy --force

echo "Documentation deployed to GitHub Pages successfully!" 