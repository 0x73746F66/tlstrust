SHELL := /bin/bash
.PHONY: help
primary := '\033[1;36m'
bold := '\033[1m'
clear := '\033[0m'

-include .env
export $(shell sed 's/=.*//' .env 2>/dev/null)
ifndef CI_BUILD_REF
CI_BUILD_REF=local
endif

ifeq ($(CI_BUILD_REF), local)
-include .env.local
export $(shell sed 's/=.*//' .env.local 2>/dev/null)
endif

ifeq ($(NODE_ENV), development)
-include .env.development
export $(shell sed 's/=.*//' .env.development 2>/dev/null)
ifeq ($(CI_BUILD_REF), local)
-include .env.development.local
export $(shell sed 's/=.*//' .env.development.local 2>/dev/null)
endif
endif

ifeq ($(NODE_ENV), production)
-include .env.production
export $(shell sed 's/=.*//' .env.production 2>/dev/null)
ifeq ($(CI_BUILD_REF), local)
-include .env.production.local
export $(shell sed 's/=.*//' .env.production.local 2>/dev/null)
endif
endif
ifndef RUNNER_NAME
RUNNER_NAME=$(shell basename $(shell pwd))
endif
ifndef CLI_VERSION
CLI_VERSION=$(shell cat ./src/tlstrust/cli/__main__.py | grep '__version__' | head -n1 | python -c "import sys; exec(sys.stdin.read()); print(__version__)")
endif

help: ## This help.
	@awk 'BEGIN {FS = ":.*?## "} /^[a-zA-Z_-]+:.*?## / {printf "\033[36m%-30s\033[0m %s\n", $$1, $$2}' $(MAKEFILE_LIST)

.DEFAULT_GOAL := help

clean: ## cleans python for wheel
	find src -type f -name '*.pyc' -delete 2>/dev/null
	find src -type d -name '__pycache__' -delete 2>/dev/null
	rm -rf build dist **/*.egg-info .pytest_cache rust-query-crlite/target
	rm -f **/*.zip **/*.tgz **/*.gz .coverage

deps: ## install dependancies for development of this project
	pip install -U --disable-pip-version-check pip
	pip install -e .

setup: deps ## setup for development of this project
	pre-commit install --hook-type pre-push --hook-type pre-commit
	@ [ -f .secrets.baseline ] || ( detect-secrets scan --exclude-files .examples/ --exclude-files src/tlstrust/stores/ > .secrets.baseline )
	detect-secrets audit .secrets.baseline

install: ## Install the package
	pip install dist/tlstrust-$(CLI_VERSION)-py2.py3-none-any.whl

reinstall: ## Force install the package
	pip install --force-reinstall -U dist/tlstrust-$(CLI_VERSION)-py3-none-any.whl

install-dev: ## Install the package
	pip install --disable-pip-version-check -U pip
	pip install -U -r requirements-dev.txt
	pip install --force-reinstall --no-cache-dir -e .

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

local-runner: ## local setup for a gitlab runner
	@docker volume create --name=gitlab-cache 2>/dev/null || true
	docker pull -q docker.io/gitlab/gitlab-runner:latest
	docker build -t $(RUNNER_NAME)/runner:${CI_BUILD_REF} .
	@echo $(shell [ -z "${RUNNER_TOKEN}" ] && echo "RUNNER_TOKEN missing" )
	@docker run -d --rm \
		--name $(RUNNER_NAME) \
		-v "gitlab-cache:/cache:rw" \
		-e RUNNER_TOKEN=${RUNNER_TOKEN} \
		$(RUNNER_NAME)/runner:${CI_BUILD_REF}
	@docker exec -ti $(RUNNER_NAME) gitlab-runner register --non-interactive \
		--tag-list 'jager' \
		--name $(RUNNER_NAME) \
		--request-concurrency 10 \
		--url https://gitlab.com/ \
		--registration-token '$(RUNNER_TOKEN)' \
		--cache-dir '/cache' \
		--executor shell
