.PHONY: geth all test lint fmt clean devtools help

GOBIN = ./build/bin
GO ?= latest
GORUN = go run
d = $(shell date -Iminutes +"%Y-%m-%d@%H_%M_%S" )

#? geth: Build geth.
geth:
	$(GORUN) build/ci.go install ./cmd/geth
	@echo "Done building."
	@echo "Run \"$(GOBIN)/geth\" to launch geth."

#? all: Build all packages and executables.
all:
	$(GORUN) build/ci.go install

cloc:
	echo ${d}
	cloc . --fullpath --exclude-dir=.idea --not-match-f="(.*?).json" | tee ./stat/${d}.txt