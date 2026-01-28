ROOT_DIR 		:= $(abspath .)
BIN_DIR			:= $(ROOT_DIR)/bin

TARGET = $(ROOT_DIR)/contract/main.go
OUTPUT = $(BIN_DIR)/main.wasm
TESTNET3 = $(BIN_DIR)/testnet3.wasm
TESTNET4 = $(BIN_DIR)/testnet4.wasm
MAINNET = $(BIN_DIR)/mainnet.wasm
BASEFLAGS = -gc=custom -scheduler=none -panic=trap -no-debug -target=wasm-unknown
TESTNET3FLAGS = -ldflags="-X 'main.NetworkMode=testnet3'"
TESTNET4FLAGS = -ldflags="-X 'main.NetworkMode=testnet4'"

TINYJSON		:= tinyjson
TINYJSON_FLAGS 	:= -snake_case -no_std_marshalers
CONTRACTS_DIR	:= contract

NETWORK ?= testnet4
FILTER ?= .

RUN_ARGS := $(wordlist 2,$(words $(MAKECMDGOALS)),$(MAKECMDGOALS))
ifneq ($(RUN_ARGS),)
  ifeq ($(firstword $(MAKECMDGOALS)),test)
    FILTER := $(firstword $(RUN_ARGS))
  else
    NETWORK := $(firstword $(RUN_ARGS))
  endif
endif
$(eval $(RUN_ARGS):;@:)

ifeq ($(NETWORK),testnet3)
CFLAGS = $(BASEFLAGS) $(TESTNET3FLAGS)
else ifeq ($(NETWORK),testnet4)
CFLAGS = $(BASEFLAGS) $(TESTNET4FLAGS)
else ifeq ($(NETWORK),mainnet)
CFLAGS = $(BASEFLAGS)
else
$(error Unknown NETWORK: $(NETWORK))
endif

all: main

main:
	@echo "Building $@ with $(NETWORK) flags"
	tinygo build $(CFLAGS) -o $(OUTPUT) $(TARGET)

testnet3: NETWORK ?= testnet3
testnet3:
	@echo "Building $@ with $(NETWORK) flags"
	tinygo build $(CFLAGS) -o $(TESTNET3) $(TARGET)

testnet4: NETWORK ?= testnet4
testnet4:
	@echo "Building $@ with $(NETWORK) flags"
	tinygo build $(CFLAGS) -o $(TESTNET4) $(TARGET)

mainnet: NETWORK ?= mainnet
mainnet:
	@echo "Building $@ with $(NETWORK) flags"
	tinygo build $(CFLAGS) -o $(MAINNET) $(TARGET)

strip:
	@for file in $(BIN_DIR)/*.wasm; do \
		case "$$file" in \
			*"-stripped.wasm") \
				continue ;; \
			*) \
				base=$${file%.wasm}; \
				wasm-tools strip -o "$${base}-stripped.wasm" "$$file"; \
				echo "Stripped $$file -> $${base}-stripped.wasm" ;; \
		esac; \
	done

tinyjson:
	@set +e; \
	echo "Searching for //tinyjson:json directives..."; \
	\
	# Ensure tinyjson exists \
	if ! command -v $(TINYJSON) >/dev/null 2>&1; then \
		echo "tinyjson not found, installing..."; \
		go install github.com/CosmWasm/tinyjson@latest || \
			{ echo "Failed to install tinyjson"; exit 1; }; \
	fi; \
	\
	# Find all directories containing files with tinyjson tags \
	find $(CONTRACTS_DIR) -type f -name '*.go' -print0 | \
	xargs -0 grep -l '^//tinyjson:json$$' | \
	xargs -n1 dirname | \
	sort -u | \
	awk '{ if ($$0 ~ /\/sdk$$/) print "0" $$0; else print "1" $$0 }' | \
	sort | \
	sed 's/^.//' | \
	while read dir; do \
		echo "Processing package in $$dir"; \
		\
		# Ensure cleanup happens on exit \
		trap 'rm -rf "$$dir/.tinyjson-tmp" 2>/dev/null' EXIT INT TERM; \
		\
		# Find the output file (assume it's *_tinyjson.go) \
		out=$$(find "$$dir" -maxdepth 1 -name '*_tinyjson.go' -print -quit); \
		\
		rebuild=0; \
		\
		# Rebuild if output missing \
		if [ -z "$$out" ] || [ ! -f "$$out" ]; then \
			echo "  Output file missing or not found"; \
			rebuild=1; \
		\
		# Rebuild if any source file with tinyjson tag is newer than output (excluding _tinyjson.go files) \
		elif find "$$dir" -maxdepth 1 -name '*.go' ! -name '*_tinyjson.go' -type f -newer "$$out" -exec grep -l '^//tinyjson:json$$' {} + | grep -q . ; then \
			echo "  Source files newer than output"; \
			rebuild=1; \
		\
		# Rebuild if output contains stub marshalers \
		elif [ -f "$$out" ] && \
			! awk '/func[[:space:]]+\([^)]+\)[[:space:]]+MarshalTinyJSON\(/ { inside=1; next } \
			inside && /\{\}[[:space:]]*$$/ { exit 1 } inside && /\{/ { inside=0 }' "$$out" && \
			! awk '/func[[:space:]]+\([^)]+\)[[:space:]]+UnmarshalTinyJSON\(/ { inside=1; next } \
			inside && /\{\}[[:space:]]*$$/ { exit 1 } inside && /\{/ { inside=0 }' "$$out"; then \
			echo "  ⚠️  stub-only function detected"; \
			rebuild=1; \
		fi; \
		\
		if [ "$$rebuild" -eq 0 ]; then \
			echo "  ⏩ $$out is up to date, skipping"; \
			continue; \
		fi; \
		\
		# Find a source file with tinyjson tag to use as template \
		src=$$(find "$$dir" -maxdepth 1 -name '*.go' -type f -exec grep -l '^//tinyjson:json$$' {} \; | head -n 1); \
		\
		if [ -z "$$src" ]; then \
			echo "  ⚠️  No source file with tinyjson tag found in $$dir"; \
			continue; \
		fi; \
		\
		if (cd $$dir && $(TINYJSON) $(TINYJSON_FLAGS) -pkg); then \
			echo "  ✅  tinyjson created for $$dir" ; \
		else \
			echo "  ⚠️  tinyjson failed for $$dir (continuing)"; \
			rm -rf "$$dir/.tinyjson-tmp" 2>/dev/null; \
		fi; \
	done

test:
	cd tests/current && go test -v -run "$(FILTER)"

clean:
	rm -rf $(BIN_DIR)/*.wasm