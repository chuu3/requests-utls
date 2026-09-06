GO ?= go

.PHONY: test race vet build check
test:
	$(GO) test ./...
race:
	$(GO) test -race ./...
vet:
	$(GO) vet ./...
build:
	$(GO) build -o bin/requests-utls ./cmd/requests-utls
check: vet race build
