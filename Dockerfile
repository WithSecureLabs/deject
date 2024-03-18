FROM ubuntu:22.04

SHELL ["/bin/bash","-c"]

COPY . /deject

WORKDIR /deject

ENV DEBIAN_FRONTEND=noninteractive

RUN apt update ; apt upgrade -y

RUN apt install git curl build-essential libffi-dev python3 python3-dev python3-pip libtool libssl-dev swig libfuzzy-dev libewf-dev libexpat1 openssl nix -y

RUN nix-channel --add https://nixos.org/channels/nixpkgs-unstable nixpkgs

RUN echo "filter-syscalls = false" >> /etc/nix/nix.conf

RUN nix-channel --update

RUN nix-env --install --attr nixpkgs.zeek nixpkgs.bulk_extractor nixpkgs.radare2

RUN ln -sf /usr/bin/python3 /usr/bin/python

RUN curl -fsSL https://raw.githubusercontent.com/python-poetry/install.python-poetry.org/main/install-poetry.py | python3

ENV PATH="/nix/var/nix/profiles/default/bin:/root/.local/bin:$PATH"

RUN echo "export PATH=$PATH" >> ~/.bashrc

RUN poetry install --compile

ENTRYPOINT ["poetry","run","deject"]
