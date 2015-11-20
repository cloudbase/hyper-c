#!/usr/bin/make
PYTHON := /usr/bin/env python
CHARM_DIR := $(PWD)
HOOKS_DIR := $(PWD)/hooks
TEST_PREFIX := PYTHONPATH=$(HOOKS_DIR)

clean:
	rm -f .coverage
	find . -name '*.pyc' -delete
	rm -rf .venv
	(which dh_clean && dh_clean) || true

.venv:
	sudo apt-get install -y gcc python-dev python-virtualenv python-apt
	virtualenv .venv --system-site-packages
	.venv/bin/pip install -I -r test-requirements.txt

lint: .venv
	@.venv/bin/flake8 --exclude hooks/charmhelpers,tests/charmhelpers hooks \
        unit_tests tests
	@charm proof

bin/charm_helpers_sync.py:
	@mkdir -p bin
	@bzr cat lp:charm-helpers/tools/charm_helpers_sync/charm_helpers_sync.py \
        > bin/charm_helpers_sync.py

sync: bin/charm_helpers_sync.py
	@$(PYTHON) bin/charm_helpers_sync.py -c charm-helpers.yaml
	@$(PYTHON) bin/charm_helpers_sync.py -c charm-helpers-tests.yaml

publish: lint
	bzr push lp:charms/rabbitmq-server
	bzr push lp:charms/trusty/rabbitmq-server

unit_test: .venv
	@echo Starting tests...
	env CHARM_DIR=$(CHARM_DIR) $(TEST_PREFIX) .venv/bin/nosetests unit_tests/

functional_test:
	@echo Starting amulet tests...
	@juju test -v -p AMULET_HTTP_PROXY,OS_USERNAME,OS_TENANT_NAME,OS_REGION_NAME,OS_PASSWORD,OS_AUTH_URL --timeout 900
