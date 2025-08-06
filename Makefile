.PHONY: help install test test-coverage lint format type-check security-check clean build publish-test publish

# Default target
help:
	@echo "Available commands:"
	@echo "  install         Install development dependencies"
	@echo "  test            Run tests"
	@echo "  test-coverage   Run tests with coverage report"
	@echo "  lint            Run flake8 linter"
	@echo "  format          Auto-format code with black and isort"
	@echo "  type-check      Run mypy type checking"
	@echo "  security-check  Run security vulnerability checks"
	@echo "  clean           Clean build artifacts"
	@echo "  build           Build distribution packages"
	@echo "  publish-test    Publish to TestPyPI"
	@echo "  publish         Publish to PyPI"

# Installation
install:
	python3 -m pip install -e ".[dev]"

# Testing
test:
	python3 -m pytest tests/ -x -s

test-specific:
	python3 -m pytest -x -s $(ARGS)

test-coverage:
	python3 -m pytest tests/ --cov=wristband --cov-report=term-missing

# Code Quality
lint:
	python3 -m flake8 src tests

format:
	python3 -m isort src tests
	python3 -m black src tests

type-check:
	python3 -m mypy src

# Security checks
security-check:
	python3 -m safety check
	python3 -m bandit -r src/

# Build and distribution
clean:
	rm -rf build/ dist/ *.egg-info/ .coverage htmlcov/ .pytest_cache/ .mypy_cache/
	find . -type d -name __pycache__ -delete
	find . -type f -name "*.pyc" -delete

build: clean
	python3 -m build

# Publishing
publish-test: build
	python3 -m twine upload --repository testpypi dist/*

publish: build
	@echo "⚠️  Publishing to PyPI! Make sure you're ready..."
	@read -p "Continue? (y/N): " confirm && [ "$confirm" = "y" ]
	python3 -m twine upload dist/*
