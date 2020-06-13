HOST=127.0.0.1
TEST_PATH=./
BASE=$(shell pwd)
ENV=${VIRTUAL_ENV}
PYTHON_VERSION := $(shell python -c 'import sys; print(".".join(map(str, sys.version_info[:2])))')

RUN_ARGS := $(wordlist 2,$(words $(MAKECMDGOALS)),$(MAKECMDGOALS))
# ...and turn them into do-nothing targets
$(eval $(RUN_ARGS):;@:)

# Export targets not associated with files
.PHONY: update

#COLORS
RED    := $(shell tput -Txterm setaf 1)
GREEN  := $(shell tput -Txterm setaf 2)
WHITE  := $(shell tput -Txterm setaf 7)
YELLOW := $(shell tput -Txterm setaf 3)
RESET  := $(shell tput -Txterm sgr0)

define print_headline
	@echo ""
	@echo "${YELLOW}*** $(1) *** ${RESET}"
	@echo ""
endef

define print_pass
	@echo "${GREEN}$(1)${RESET}"
endef

define print_fail
	@echo "${RED}$(1)${RESET}"
endef

# Add the following 'help' target to your Makefile
# And add help text after each target name starting with '\#\#'
# A category can be added with @category
HELP_FUN = \
    %help; \
    while(<>) { push @{$$help{$$2 // 'options'}}, [$$1, $$3] if /^([0-9a-zA-Z\-\.]+)\s*:.*\#\#(?:@([0-9a-zA-Z\-\.]+))?\s(.*)$$/ }; \
    print "usage: make [target]\n\n"; \
    for (sort keys %help) { \
    print "${WHITE}$$_:${RESET}\n"; \
    for (@{$$help{$$_}}) { \
    $$sep = " " x (32 - length $$_->[0]); \
    print "  ${YELLOW}$$_->[0]${RESET}$$sep${GREEN}$$_->[1]${RESET}\n"; \
    }; \
    print "\n"; }

help: ##@other Show this help.
	@perl -e '$(HELP_FUN)' $(MAKEFILE_LIST)

check-env: ## Checks if the python virtual environment exists.
	@if [ "x${ENV}" = "x" ]; then echo "Virtual environment is not set, exiting"; exit 1; else echo "Virtual environment is set"; fi

clean: ## Cleans up the development environment.
	$(call print_headline,"Cleaning up the pyc files")
	find . -name "*.pyc" -print0 | xargs -0 rm -rf
	-rm -rf htmlcov
	-rm -rf .coverage
	-rm -rf dist
	find . -type d -name "__pycache__" -exec rm -rf {} +
	find . -type d -name ".cache" -exec rm -rf {} +

install-pkgs: ##@Setup Installs all the dependent python packages from requirements file
	$(call print_headline,"Installing/Updating the package requirements")
	pip3 install -q -r requirements.txt

setup-env: ##@Setup Creates a new python 3+ virtual environment
	$(call print_headline,"Creating python virtual environment")
	virtualenv -p /usr/bin/python3 venv3
	. ./venv3/bin/activate &&\
	pip3 install --upgrade pip &&\
	pip3 install -q -r requirements.txt
	$(call print_headline,"Activate the virtual environment using: source venv3/bin/activate")