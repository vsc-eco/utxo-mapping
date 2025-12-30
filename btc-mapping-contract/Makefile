TARGET = ./contract/main.go
OUTPUT = artifacts/main.wasm
TESTNET3 = artifacts/testnet3.wasm
TESTNET4 = artifacts/testnet4.wasm
MAINNET = artifacts/mainnet.wasm
BASEFLAGS = -gc=custom -scheduler=none -panic=trap -no-debug -target=wasm-unknown
TESTNET3FLAGS = -ldflags="-X 'main.NetworkMode=testnet3'"
TESTNET4FLAGS = -ldflags="-X 'main.NetworkMode=testnet4'"

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
	wasm-tools strip -o artifacts/main-stripped.wasm $(OUTPUT)
	wasm-tools strip -o artifacts/testnet3-stripped.wasm $(TESTNET3)
	wasm-tools strip -o artifacts/testnet4-stripped.wasm $(TESTNET4)
	wasm-tools strip -o artifacts/mainnet-stripped.wasm $(MAINNET)

clean:
	rm -rf artifacts/*.wasm