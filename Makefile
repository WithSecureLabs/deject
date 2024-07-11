.PHONY: all default arm64 amd64 poetry flake

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

flake:
	sudo nix build .
