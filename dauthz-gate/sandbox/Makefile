# dauthz-gate sandbox — the whole flow on one machine, headless or with a real wallet.
#
#   make build            build cyfron-serviced and dauthz-gate release binaries on the host
#   make up               start nginx + site + gate + two daemons (policy: open)
#   make smoke            headless sign-in as "alice" (user daemon signs the challenge)
#   make passport         alice gets a passport from the sandbox authority; gate -> credential mode
#   make smoke-credential headless sign-in presenting the passport
#   make smoke-bare       sign in without the passport in credential mode: parked on /dauthz/present
#   make smoke-present-page  same, then paste the proof on /dauthz/present
#   make revoke smoke-revoked   revoke the passport in the TEL; both paths must refuse it
#   make status / logs / down / reset
#
# Browser test: open $(SITE_URL) and Connect with Cyfron from a desktop wallet
# (or scan the QR with a phone on the LAN). The wallet must reach SITE_ORIGIN.

SHELL := /bin/bash
SANDBOX_DIR := $(dir $(abspath $(lastword $(MAKEFILE_LIST))))
DAUTHZ_ROOT ?= $(abspath $(SANDBOX_DIR)/../..)
CYFRON_MONO ?= /mnt/Storage/Workspace/ArgonAUTHs/sources/cyfron
CYFRON_BIN  ?= $(CYFRON_MONO)/target/release/cyfron-serviced
GATE_BIN    ?= $(DAUTHZ_ROOT)/target/release/dauthz-gate

# Wallets on other devices must reach the site: default to the LAN IP.
HOST_IP     ?= $(shell ip route get 1.1.1.1 2>/dev/null | sed -n 's/.*src \([0-9.]*\).*/\1/p')
HOST_IP     := $(or $(strip $(HOST_IP)),localhost)
SITE_PORT   ?= 8080
SITE_ORIGIN ?= http://$(HOST_IP):$(SITE_PORT)
SITE_URL    ?= http://localhost:$(SITE_PORT)
USER_PORT   ?= 51235
SP_TOKEN    ?= sandbox-sp-token
USER_TOKEN  ?= sandbox-user-token
MESAGKESTO_URL   ?= https://messagebox.dkms.colossi.network
WITNESS_LOCATION ?= {"eid":"BJq7UABlttINuWJh1Xl2lkqZG4NTdUdqnbFJDa6ZyxCC","scheme":"http","url":"http://witness1.dkms.colossi.network/"}
WATCHER_LOCATION ?= {"eid":"BF2t2NPc1bwptY1hYV0YCib1JjQ11k9jtuaZemecPF5b","scheme":"http","url":"http://watcher.dkms.colossi.network/"}
SCHEMA_SAID ?= ELoHlOIHQQ3vkA-erKdD5ab9w9eij2Y4hjoYox6cS7wu

export CYFRON_BIN GATE_BIN SITE_ORIGIN SITE_PORT USER_PORT SP_TOKEN USER_TOKEN MESAGKESTO_URL WITNESS_LOCATION WATCHER_LOCATION
SMOKE := $(DAUTHZ_ROOT)/dauthz-gate/scripts/smoke-callback.sh
USER_ENV := CYFRON_URL=http://127.0.0.1:$(USER_PORT) CYFRON_TOKEN=$(USER_TOKEN) WITNESS_LOCATION='$(WITNESS_LOCATION)' WATCHER_LOCATION='$(WATCHER_LOCATION)'

.PHONY: build build-serviced build-gate up down reset restart-gate logs status wait smoke smoke-credential smoke-bare smoke-present-page passport revoke smoke-revoked

build: build-serviced build-gate

build-serviced:
	cd $(CYFRON_MONO) && cargo build --release -p cyfron-serviced

build-gate:
	cd $(DAUTHZ_ROOT) && cargo build --release -p dauthz-gate

.env.policy:
	@printf 'DAUTHZ_POLICY__MODE=open\n' > .env.policy
	@echo "-> .env.policy created (policy: open). 'make passport' switches to credential mode."

# docker compose reads .env on its own, so plain `docker compose logs …`
# works after the first `make up` without re-exporting everything.
.PHONY: dotenv
dotenv:
	@{ \
	  echo "CYFRON_BIN=$(CYFRON_BIN)"; echo "GATE_BIN=$(GATE_BIN)"; \
	  echo "SITE_ORIGIN=$(SITE_ORIGIN)"; echo "SITE_PORT=$(SITE_PORT)"; echo "USER_PORT=$(USER_PORT)"; \
	  echo "SP_TOKEN=$(SP_TOKEN)"; echo "USER_TOKEN=$(USER_TOKEN)"; echo "MESAGKESTO_URL=$(MESAGKESTO_URL)"; \
	  echo "WITNESS_LOCATION=$(WITNESS_LOCATION)"; echo "WATCHER_LOCATION=$(WATCHER_LOCATION)"; \
	} > .env

up: .env.policy dotenv
	@test -x $(CYFRON_BIN) || (echo "missing $(CYFRON_BIN): run make build" >&2; exit 1)
	@test -x $(GATE_BIN) || (echo "missing $(GATE_BIN): run make build" >&2; exit 1)
	docker compose up -d --build
	@$(MAKE) --no-print-directory wait
	@echo "-> site: $(SITE_URL)   (wallets use $(SITE_ORIGIN))"

wait:
	@echo "-> waiting for the gate to bootstrap its service identity (first start talks to the witness)"
	@for i in $$(seq 1 120); do \
	  if curl -fsS $(SITE_URL)/dauthz/healthz >/dev/null 2>&1; then curl -sS $(SITE_URL)/dauthz/healthz; echo; exit 0; fi; sleep 2; done; \
	  echo "gate not ready; see make logs" >&2; exit 1

down:
	docker compose down

reset:
	docker compose down -v
	rm -f .env.policy state/passport.json

restart-gate:
	docker compose up -d --force-recreate dauthz-gate
	@$(MAKE) --no-print-directory wait

logs:
	docker compose logs -f dauthz-gate sp-cyfron user-cyfron

status:
	@curl -sS $(SITE_URL)/dauthz/healthz | python3 -m json.tool
	@echo "policy file:"; cat .env.policy

smoke:
	$(USER_ENV) USER_ALIAS=alice SITE_URL=$(SITE_URL) bash $(SMOKE)

passport:
	$(USER_ENV) SCHEMA_SAID=$(SCHEMA_SAID) OUT=state/passport.json POLICY_FILE=.env.policy bash ./passport.sh
	@$(MAKE) --no-print-directory restart-gate

smoke-credential:
	@test -f state/passport.json || (echo "run make passport first" >&2; exit 1)
	$(USER_ENV) USER_ALIAS=alice PRESENT_FILE=state/passport.json SITE_URL=$(SITE_URL) bash $(SMOKE)

smoke-bare:
	$(USER_ENV) USER_ALIAS=alice SITE_URL=$(SITE_URL) bash $(SMOKE)

# Sign in without the passport, then paste it on /dauthz/present (the path
# for wallets that do not carry requested_credentials yet).
smoke-present-page:
	@test -f state/passport.json || (echo "run make passport first" >&2; exit 1)
	$(USER_ENV) USER_ALIAS=alice PRESENT_FILE=state/passport.json PRESENT_MODE=page SITE_URL=$(SITE_URL) bash $(SMOKE)

# Revoke the passport in the authority's TEL, then show both presentation
# paths refuse it (policy revocation_check=if_known asks the registry).
revoke:
	@test -f state/passport.json || (echo "run make passport first" >&2; exit 1)
	curl -fsS -H "Authorization: Bearer $(USER_TOKEN)" -X POST \
	  "http://127.0.0.1:$(USER_PORT)/governance/$$(jq -r .governance_id state/passport.json)/issued/$$(jq -r .said state/passport.json)/revoke" | jq '{said, tel_status}'

smoke-revoked:
	$(USER_ENV) USER_ALIAS=alice PRESENT_FILE=state/passport.json EXPECT_DENY=1 SITE_URL=$(SITE_URL) bash $(SMOKE)
	$(USER_ENV) USER_ALIAS=alice PRESENT_FILE=state/passport.json PRESENT_MODE=page EXPECT_DENY=1 SITE_URL=$(SITE_URL) bash $(SMOKE)
