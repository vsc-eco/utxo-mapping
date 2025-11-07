TARGET = ./contract/main.go
OUTPUT = artifacts/main.wasm
TESTNET = artifacts/testnet3.wasm
MAINNET = artifacts/mainnet.wasm
FLAGS = -gc=custom -scheduler=none -panic=trap -no-debug -target=wasm-unknown
TESTNETFLAGS = $(FLAGS) -ldflags="-X 'main.NetworkMode=testnet'"

all: build

build:
	tinygo build $(TESTNETFLAGS) -o $(OUTPUT) $(TARGET)

testnet:
	tinygo build $(TESTNETFLAGS) -o $(TESTNET) $(TARGET)

mainnet:
	tinygo build $(FLAGS) -o $(MAINNET) $(TARGET)

strip:
	wasm-tools strip -o artifacts/main-stripped.wasm $(OUTPUT)
	wasm-tools strip -o artifacts/testnet3-stripped.wasm $(TESTNET)
	wasm-tools strip -o artifacts/mainnet-stripped.wasm $(MAINNET)

clean:
	rm -rf artifacts/*.wasm