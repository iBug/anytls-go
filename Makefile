GORELEASER_FLAGS ?= --snapshot --clean --skip=publish,archive

.PHONY: all

all:
	goreleaser release $(GORELEASER_FLAGS)

check:
	goreleaser check

clean:
	rm -rf dist
