ROOT_DIR 		:= $(abspath .)
BIN_DIR			:= bin

TARGET = contract/main.go
BASEFLAGS = -gc=custom -scheduler=none -panic=trap -no-debug -target=wasm-unknown
TESTNET3FLAGS = -ldflags="-X 'main.NetworkMode=testnet3'"
TESTNET4FLAGS = -ldflags="-X 'main.NetworkMode=testnet4'"

TINYJSON		:= tinyjson
TINYJSON_FLAGS 	:= -snake_case -no_std_marshalers
CONTRACTS_DIR	:= contract

TINYGO_IMAGE := tinygo/tinygo:0.39.0
WORKDIR      := /work
DOCKER_TINYGO = docker run --rm \
	-e HOME=/tmp \
	-v $(CURDIR):$(WORKDIR) \
	-w $(WORKDIR) \
	$(TINYGO_IMAGE) \
	tinygo

TINYGO_CMD = tinygo

ifdef USE_DOCKER
    TINYGO_CMD = docker run --rm \
        -u $(shell id -u):$(shell id -g) \
        -v $(CURDIR):$(WORKDIR) \
        -w $(WORKDIR) \
        $(TINYGO_IMAGE) \
        tinygo
endif

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

CFLAGS = $(BASEFLAGS) $(call netflags,$(NETWORK))

netflags = \
	$(if $(filter testnet3,$1),$(TESTNET3FLAGS), \
	$(if $(filter testnet4,$1),$(TESTNET4FLAGS), \
	$(if $(filter mainnet,$1),, \
	$(error Unknown NETWORK: $1))))

all: dev

pull-tinygo:
	docker pull $(TINYGO_IMAGE)

dev:
	@echo "Building $@ with $(NETWORK) flags"
	$(TINYGO_CMD) build $(CFLAGS) -o $(BIN_DIR)/$@.wasm $(TARGET)

testnet3: NETWORK ?= testnet3
testnet3:
	@echo "Building $@ with $(NETWORK) flags"
	$(TINYGO_CMD) build $(CFLAGS) -o $(BIN_DIR)/$@.wasm $(TARGET)

testnet4: NETWORK ?= testnet4
testnet4:
	@echo "Building $@ with $(NETWORK) flags"
	$(TINYGO_CMD) build $(CFLAGS) -o $(BIN_DIR)/$@.wasm $(TARGET)

mainnet: NETWORK ?= mainnet
mainnet:
	@echo "Building $@ with $(NETWORK) flags"
	$(TINYGO_CMD) build $(CFLAGS) -o $(BIN_DIR)/$@.wasm $(TARGET)

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
	find $(ROOT_DIR) -type f -name '*.go' -print0 | \
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
		# Get the original package name \
		original_pkg=$$(awk '/^package / {print $$2; exit}' "$$src"); \
		\
		if [ -z "$$original_pkg" ]; then \
			echo "  ⚠️  Could not determine package name in $$src"; \
			continue; \
		fi; \
		\
		if (mkdir -p "$$dir/.tinyjson-tmp" && \
			find "$$dir" -maxdepth 1 -name '*.go' ! -name '*_tinyjson.go' ! -name '*_test.go' -exec cp {} "$$dir/.tinyjson-tmp/" \; && \
			cd "$$dir/.tinyjson-tmp" && \
			for f in *.go; do \
				awk '/^package / {sub(/package .*/, "package tinyjson")} {print}' "$$f" > "$$f.tmp" && mv "$$f.tmp" "$$f"; \
			done && \
			$(TINYJSON) $(TINYJSON_FLAGS) -pkg -output_filename "$${original_pkg}_tinyjson.go" && \
			for f in *_tinyjson.go; do \
				[ -f "$$f" ] && sed "s/package tinyjson/package $$original_pkg/" "$$f" > "../$$f"; \
			done && \
			cd .. && \
			rm -rf .tinyjson-tmp); then \
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