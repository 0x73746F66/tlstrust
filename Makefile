SHELL := /bin/bash
-include .env
export $(shell sed 's/=.*//' .env)
.PHONY: help

help: ## This help.
	@awk 'BEGIN {FS = ":.*?## "} /^[a-zA-Z_-]+:.*?## / {printf "\033[36m%-30s\033[0m %s\n", $$1, $$2}' $(MAKEFILE_LIST)

.DEFAULT_GOAL := help

ifndef CLI_VERSION
CLI_VERSION=$(shell cat ./src/tlstrust/cli/__main__.py | grep '__version__' | head -n1 | python -c "import sys; exec(sys.stdin.read()); print(__version__)")
endif


deps: ## install dependancies for development of this project
	python -m pip install -U pip
	python -m pip install -U -r requirements-dev.txt
	python -m pip install --force-reinstall --no-cache-dir -e .

setup: deps ## setup for development of this project
	pre-commit install --hook-type pre-push --hook-type pre-commit
	@ [ -f .secrets.baseline ] || ( detect-secrets scan --exclude-files .examples/ --exclude-files src/tlstrust/stores/ > .secrets.baseline )
	detect-secrets audit .secrets.baseline

install: ## Install the package
	python -m pip install dist/tlstrust-$(CLI_VERSION)-py2.py3-none-any.whl

reinstall: ## Force install the package
	python -m pip install --force-reinstall -U dist/tlstrust-$(CLI_VERSION)-py3-none-any.whl

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

build: ## build wheel file
	rm -f dist/*
	python -m build -nxsw

pypi: ## upload to pypi.org
	git tag -f $(CLI_VERSION)
	git push -u origin --tags -f
	python -m twine upload dist/*

tag: ## tag release and push
	git tag -f $(CLI_VERSION)
	git push -u origin --tags -f

publish: pypi tag ## upload to pypi.org and push git tags

test-local: ## Prettier test outputs
	pylint --exit-zero -f colorized --persistent=y -r y --jobs=0 src/**/*.py
	semgrep -q --strict --timeout=0 --config=p/r2c-ci --lang=py src/**/*.py

pylint-ci: ## run pylint for CI
	pylint --exit-zero --persistent=n -f json -r n --jobs=0 --errors-only src/**/*.py > pylint.json

semgrep-sast-ci: ## run core semgrep rules for CI
	semgrep --disable-version-check -q --strict --error -o semgrep-ci.json --json --timeout=0 --config=p/r2c-ci --lang=py src/**/*.py

test-all: semgrep-sast-ci pylint-ci ## Run all CI tests
