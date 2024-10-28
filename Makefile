ifdef CI
	DOCKER_PHP_EXEC :=
else
	DOCKER_PHP_EXEC := docker compose run --rm php
endif

SRCS := $(shell find ./src ./test -type f)

default: unit cs static-analysis coverage ## all the things

.PHONY: help
help:
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | sort | awk 'BEGIN {FS = ":.*?## "}; {printf "\033[36m%-30s\033[0m %s\n", $$1, $$2}'

.env: /etc/passwd /etc/group Makefile
	printf "USER_ID=%s\nGROUP_ID=%s\n" `id --user "${USER}"` `id --group "${USER}"` > .env

vendor: .env docker-compose.yml Dockerfile composer.json
	docker compose build --pull
	$(DOCKER_PHP_EXEC) composer update
	$(DOCKER_PHP_EXEC) composer bump
	touch --no-create $@

.PHONY: unit
unit: vendor ## run unit tests
	$(DOCKER_PHP_EXEC) vendor/bin/phpunit

.PHONY: cs
cs: vendor ## verify code style rules
	$(DOCKER_PHP_EXEC) vendor/bin/phpcbf -p || true
	$(DOCKER_PHP_EXEC) vendor/bin/phpcs -p

.PHONY: static-analysis
static-analysis: vendor ## verify that no static analysis issues were introduced
	$(DOCKER_PHP_EXEC) vendor/bin/psalm

.PHONY: bc-check
bc-check: vendor ## check for backwards compatibility breaks
	mkdir -p /tmp/bc-check
	$(DOCKER_PHP_EXEC) composer require --no-plugins -d/tmp/bc-check roave/backward-compatibility-check 
	$(DOCKER_PHP_EXEC) /tmp/bc-check/vendor/bin/roave-backward-compatibility-check
	rm -Rf /tmp/bc-check

.PHONY: coverage
coverage: vendor ## generate code coverage reports
	$(DOCKER_PHP_EXEC) vendor/bin/roave-infection-static-analysis-plugin --show-mutations

.PHONY: clean
clean:
	git clean -dfX
