SHELL := /bin/bash
.PHONY: help

help: ## This help.
	@awk 'BEGIN {FS = ":.*?## "} /^[a-zA-Z_-]+:.*?## / {printf "\033[36m%-30s\033[0m %s\n", $$1, $$2}' $(MAKEFILE_LIST)

.DEFAULT_GOAL := help

install-deps: ## setup for development of this project
	pip install -U --progress-bar off pip setuptools wheel semgrep pylint pytest build twine coverage

install: build ## Install the package
	pip install -U --progress-bar off --no-cache-dir --force-reinstall dist/tlstrust-$(shell cat ./setup.py | grep 'version=' | sed 's/[version=", ]//g')-py2.py3-none-any.whl

check: ## check build
	python3 setup.py check

test: generate-files ## run unit tests with coverage
	coverage run -m pytest --nf -s
	coverage report -m

generate-files: ## generates trust store files
	bin/parse_android
	bin/parse_ccadb
	bin/parse_certifi
	bin/parse_java
	bin/parse_linux

build: check ## build wheel file
	rm -f dist/*
	python3 -m build -nx

publish: build ## upload to pypi.org
	git tag $(shell cat ./setup.py | grep 'version=' | sed 's/[version=", ]//g')
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
