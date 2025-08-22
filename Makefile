GO ?= go
DOCKER ?= docker
MAKE ?= make

COMMIT_HASH := $(shell git describe --match "v[0-9]" --always)
BUILD_VERSION ?= $(shell date -u +%Y%m%d.%H%M)

PLATFORMS := linux/amd64
PLATFORMS += linux/arm64

APP := ztr

BINARIES := $(foreach PLATFORM,$(PLATFORMS),$(addprefix build/$(PLATFORM)/,$(APP)))

$(BINARIES): build/%/$(APP): build/%
	CGO_ENABLED=0 \
	GOOS=$(word 1,$(subst /, ,$*)) \
	GOARCH=$(word 2,$(subst /, ,$*)) \
	$(GO) build \
		-ldflags "-X main.buildVersion=$(BUILD_VERSION) -X main.commitHash=$(COMMIT_HASH)" -o $@ .

build/%:
	mkdir -p $@

.PHONY: all
all: build

.PHONY: build
build: $(BINARIES)

.PHONY: clean
clean:
	rm -rf build