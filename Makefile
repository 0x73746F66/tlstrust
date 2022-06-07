SHELL := /bin/bash
-include .env
export $(shell sed 's/=.*//' .env)
.PHONY: help

help: ## This help.
	@awk 'BEGIN {FS = ":.*?## "} /^[a-zA-Z_-]+:.*?## / {printf "\033[36m%-30s\033[0m %s\n", $$1, $$2}' $(MAKEFILE_LIST)

.DEFAULT_GOAL := help

deps: ## install dependancies for development of this project
	python -m pip install -U pip
	python -m pip install -U -r requirements-dev.txt
	python -m pip install --force-reinstall --no-cache-dir -e .

setup: deps ## setup for development of this project
	pre-commit install --hook-type pre-push --hook-type pre-commit
	@ [ -f .secrets.baseline ] || ( detect-secrets scan --exclude-files .examples/ --exclude-files src/tlstrust/stores/ > .secrets.baseline )
	detect-secrets audit .secrets.baseline

install: ## Install the package
	python -m pip install dist/tlstrust-$(shell cat ./setup.py | grep '__version__' | sed 's/[_version=", ]//g' | head -n1)-py2.py3-none-any.whl

check: ## check build
	python3 setup.py check

test: ## run unit tests with coverage
	coverage run -m pytest --nf -s
	coverage report -m

generate-files: ## generates trust store files
	mkdir -p .data/java
	bin/parse_android
	bin/parse_ccadb
	bin/parse_certifi
	bin/parse_curl
	bin/parse_dart
	bin/parse_java
	bin/parse_russian
	bin/parse_rustls

build: check ## build wheel file
	rm -f dist/*
	python3 -m build -nx

publish: build ## upload to pypi.org
	git tag -f $(shell cat ./setup.py | grep 'version=' | sed 's/[version=", ]//g')
	git push -u origin --tags
	python3 -m twine upload dist/*

test-local: ## Prettier test outputs
	pylint --exit-zero -f colorized --persistent=y -r y --jobs=0 src/**/*.py
	semgrep -q --strict --timeout=0 --config=p/r2c-ci --lang=py src/**/*.py

pylint-ci: ## run pylint for CI
	pylint --exit-zero --persistent=n -f json -r n --jobs=0 --errors-only src/**/*.py > pylint.json

semgrep-sast-ci: ## run core semgrep rules for CI
	semgrep --disable-version-check -q --strict --error -o semgrep-ci.json --json --timeout=0 --config=p/r2c-ci --lang=py src/**/*.py

test-all: semgrep-sast-ci pylint-ci ## Run all CI tests
