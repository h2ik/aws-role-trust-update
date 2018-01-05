SHELL := /bin/bash
BINARY=aws-role-trust-update
PACKAGE=github.com/h2ik/aws-role-trust-update

LDFLAGS=-ldflags "-s -w"
GCFLAGS=-gcflags "-N -l"

.DEFAULT_GOAL: $(BINARY)
.PHONY: $(BINARY) clean

$(BINARY): clean
	export CGO_ENABLED=0 && go build ${LDFLAGS} ${GCFLAGS} -o bin/${BINARY} ${PACKAGE}

clean:
	rm -Rf bin/*
