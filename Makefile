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
	@#cloc . --exclude-ext=json,js,txt,c,h,sol --not-match-f="(.*?).pb.go" --not-match-f="(.*?)_test.go" | tee ./stat/${d}.txt
	cloc . --exclude-ext=json,js,txt,c,h,sol  --not-match-f="(.*?).pb.go"--not-match-f="(.*?).pb.go" --not-match-f="(.*?)_test.go"  --fullpath --not-match-d=crypto/secp256k1 | tee ./stat/${d}.txt