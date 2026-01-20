TARGET = ./contract/main.go
OUTPUT = artifacts/main.wasm
TESTNET3 = artifacts/testnet3.wasm
TESTNET4 = artifacts/testnet4.wasm
MAINNET = artifacts/mainnet.wasm
BASEFLAGS = -gc=custom -scheduler=none -panic=trap -no-debug -target=wasm-unknown
TESTNET3FLAGS = -ldflags="-X 'main.NetworkMode=testnet3'"
TESTNET4FLAGS = -ldflags="-X 'main.NetworkMode=testnet4'"

TINYJSON 		:= tinyjson
TINYJSON_FLAGS 	:= -snake_case -no_std_marshalers
CONTRACTS_DIR	:= contract

NETWORK ?= testnet4

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
	@for file in artifacts/*.wasm; do \
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
	find $(CONTRACTS_DIR) -type f -name '*.go' -print0 | \
	xargs -0 grep -l '^//tinyjson:json$$' | \
	xargs -n1 dirname | sort -u | while read dir; do \
		name=$$(basename "$$dir"); \
		out="$$dir/$${name}_tinyjson.go"; \
		echo "Processing $$dir"; \
		\
		# Check if output exists and is up to date \
		if [ -f "$$out" ]; then \
			newer=0; \
			for f in "$$dir"/*.go; do \
				if [ "$$f" -nt "$$out" ]; then newer=1; break; fi; \
			done; \
			if [ "$$newer" -eq 0 ]; then \
				echo "  ✓ $$out is up to date, skipping"; \
				continue; \
			fi; \
		fi; \
		\
		(cd "$$dir" && \
			$(TINYJSON) $(TINYJSON_FLAGS) .) || \
		echo "⚠️  tinyjson failed for $$dir (continuing)"; \
	done

clean:
	rm -rf artifacts/*.wasm