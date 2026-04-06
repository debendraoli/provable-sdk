.PHONY: build-rust clean test test-unit test-integration lint bench install-lib

# Detect OS for library extension
UNAME_S := $(shell uname -s)
ifeq ($(UNAME_S),Darwin)
	LIB_EXT := dylib
	LIB_PREFIX := lib
else
	LIB_EXT := so
	LIB_PREFIX := lib
endif

RUST_LIB := rust-bridge/target/release/$(LIB_PREFIX)aleo_bridge.$(LIB_EXT)
RUST_DIR := rust-bridge

CGO_ENV := CGO_ENABLED=1 \
	CGO_LDFLAGS="-L$(CURDIR)/$(RUST_DIR)/target/release" \
	LD_LIBRARY_PATH="$(CURDIR)/$(RUST_DIR)/target/release:$$LD_LIBRARY_PATH" \
	DYLD_LIBRARY_PATH="$(CURDIR)/$(RUST_DIR)/target/release:$$DYLD_LIBRARY_PATH"

build-rust:
	cd $(RUST_DIR) && cargo build --release
	@echo "Built: $(RUST_LIB)"

clean-rust:
	cd $(RUST_DIR) && cargo clean

test-rust:
	cd $(RUST_DIR) && cargo test

lint-rust:
	cd $(RUST_DIR) && cargo clippy -- -D warnings

test: build-rust
	$(CGO_ENV) go test -v -count=1 ./...

test-unit: build-rust
	$(CGO_ENV) go test -v -count=1 ./...

test-integration: build-rust
	$(CGO_ENV) go test -v -tags=integration -count=1 ./...

lint: build-rust
	$(CGO_ENV) go vet ./...
	@echo "go vet passed"

bench: build-rust
	$(CGO_ENV) go test -bench=. -benchmem -count=1 ./...

build: build-rust
	$(CGO_ENV) go build ./...

clean: clean-rust
	go clean ./...

INSTALL_DIR ?= /usr/local/lib

install-lib: build-rust
	@echo "Installing $(RUST_LIB) to $(INSTALL_DIR)"
	install -d $(INSTALL_DIR)
	install -m 755 $(RUST_LIB) $(INSTALL_DIR)/
ifeq ($(UNAME_S),Linux)
	ldconfig || true
endif
	@echo "Done. You can now: go get github.com/debendraoli/provable-sdk"

help:
	@echo "Available targets:"
	@echo "  build-rust        Build the Rust FFI bridge"
	@echo "  test-rust         Run Rust unit tests"
	@echo "  lint-rust         Run cargo clippy"
	@echo "  build             Build Rust bridge + Go package"
	@echo "  test              Run all Go tests (builds Rust first)"
	@echo "  test-unit         Run unit tests only"
	@echo "  test-integration  Run integration tests (needs network)"
	@echo "  lint              Run go vet"
	@echo "  install-lib       Build and install native lib to /usr/local/lib"
	@echo "  clean             Clean all build artifacts"
