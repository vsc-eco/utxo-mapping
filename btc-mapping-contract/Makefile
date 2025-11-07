TARGET = ./contract/main.go
OUTPUT = artifacts/main.wasm
TESTNET = artifacts/testnet3.wasm
MAINNET = artifacts/mainnet.wasm
BASEFLAGS = -gc=custom -scheduler=none -panic=trap -no-debug -target=wasm-unknown
TESTNETFLAGS = -ldflags="-X 'main.NetworkMode=testnet'"

NETWORK ?= testnet

ifeq ($(NETWORK),testnet)
CFLAGS = $(BASEFLAGS) $(TESTNETFLAGS)
else ifeq ($(NETWORK),mainnet)
CFLAGS = $(BASEFLAGS)
else
$(error Unknown NETWORK: $(NETWORK))
endif

all: build

build:
	@echo "Building $@ with $(NETWORK) flags"
	tinygo build $(CFLAGS) -o $(OUTPUT) $(TARGET)

testnet:
	@echo "Building $@ with $(NETWORK) flags"
	tinygo build $(CFLAGS) -o $(TESTNET) $(TARGET)

mainnet: NETWORK ?= mainnet
mainnet:
	@echo "Building $@ with $(NETWORK) flags"
	tinygo build $(CFLAGS) -o $(MAINNET) $(TARGET)

strip:
	wasm-tools strip -o artifacts/main-stripped.wasm $(OUTPUT)
	wasm-tools strip -o artifacts/testnet3-stripped.wasm $(TESTNET)
	wasm-tools strip -o artifacts/mainnet-stripped.wasm $(MAINNET)

clean:
	rm -rf artifacts/*.wasm