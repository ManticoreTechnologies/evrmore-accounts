# Evrmore Accounts Makefile
# Provides commands for development, testing, and deployment

.PHONY: install dev-setup run dev run-gunicorn test test-unit test-integration test-security test-all \
        healthcheck clean lint format build-docs

# Python and paths
PYTHON := python3
PIP := pip3
PYTEST := pytest
PROJECT_ROOT := $(shell pwd)
SCRIPTS_DIR := $(PROJECT_ROOT)/scripts

# Configuration
PORT ?= 5000
HOST ?= 0.0.0.0
DEBUG ?= false
WORKERS ?= 4
TIMEOUT ?= 120

# Installation
install:
	$(PIP) install -e .

dev-setup:
	$(PIP) install -e ".[dev]"

# Running the server
run:
	$(PYTHON) $(SCRIPTS_DIR)/run.py --host $(HOST) --port $(PORT)

dev:
	DEBUG=true $(PYTHON) $(SCRIPTS_DIR)/run.py --host $(HOST) --port $(PORT) --debug

run-gunicorn:
	HOST=$(HOST) PORT=$(PORT) WORKERS=$(WORKERS) TIMEOUT=$(TIMEOUT) $(SCRIPTS_DIR)/run_gunicorn.sh

# Testing
test:
	$(PYTHON) -m tests.integration.test_backend

test-unit:
	$(PYTHON) -m tests.unit.db_test

test-security:
	$(PYTHON) -m tests.security.test_security

test-all:
	$(PYTHON) -m tests.unit.db_test && \
	$(PYTHON) -m tests.integration.test_backend && \
	$(PYTHON) -m tests.security.test_security

# Health check
healthcheck:
	$(PYTHON) -m evrmore_accounts.healthcheck --url http://$(HOST):$(PORT)

# Cleanup
clean:
	rm -rf build/ dist/ *.egg-info/ __pycache__/ .pytest_cache/ .coverage
	find . -name __pycache__ -exec rm -rf {} +
	find . -name "*.pyc" -delete
	find . -name "*.pyo" -delete
	find . -name "*.pyd" -delete

# Code quality
lint:
	flake8 evrmore_accounts tests

format:
	black evrmore_accounts tests

# Documentation
build-docs:
	cd docs && $(MAKE) html 