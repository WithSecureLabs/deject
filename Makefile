.PHONY: all default arm64 amd64 poetry flake install-deps

default:
	sudo docker build -t deject .

all: multi

arm64:
	sudo docker build -t deject . --platform linux/arm64

amd64:
	sudo docker build -t deject . --platform linux/amd64

multi:
	sudo docker run --rm --privileged multiarch/qemu-user-static --reset -p yes
	$(MAKE) amd64
	$(MAKE) arm64

poetry:
	poetry install --compile

install-deps:
	sudo apt install git curl build-essential libffi-dev python3 python3-dev python3-pip libtool libssl-dev swig libfuzzy-dev libewf-dev libexpat1 openssl

flake:
	sudo nix build .
