.PHONY: build-lbac-server

build-lbac-server:
	docker build -t quay.io/philipgough/lbac:latest -f cmd/lbac/Dockerfile .
