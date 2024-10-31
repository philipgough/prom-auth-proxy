.PHONY: build-lbac-server
build-lbac-server:
	docker build -t quay.io/philipgough/lbac:latest -f cmd/lbac-ext-proc/Dockerfile .

.PHONY: build-token-review-server
build-token-review-server:
	docker build -t quay.io/philipgough/token-review:latest -f cmd/token-review-ext-authz/Dockerfile .
