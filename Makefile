GO ?= go

.PHONY: test race vet build shared testpeer check
test:
	$(GO) test ./...
race:
	$(GO) test -race ./...
vet:
	$(GO) vet ./...
build:
	$(GO) build -o bin/requests-utls ./cmd/requests-utls
shared:
	$(GO) build -buildmode=c-shared -o dist/librequests_utls$(if $(filter Windows_NT,$(OS)),.dll,$(if $(filter Darwin,$(shell uname -s)),.dylib,.so)) ./cmd/requests-utls-shared
testpeer:
	$(GO) build -o bin/requests-utls-testpeer$(if $(filter Windows_NT,$(OS)),.exe,) ./cmd/requests-utls-testpeer
check: vet race build
