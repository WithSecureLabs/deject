FROM ubuntu:24.04

SHELL ["/bin/bash","-c"]

WORKDIR /deject

ENV DEBIAN_FRONTEND=noninteractive

RUN apt update ; apt upgrade -y \
&& apt install git curl build-essential libffi-dev python3 python3-dev python3-pip libtool libssl-dev swig libfuzzy-dev libewf-dev libexpat1 openssl nix -y

RUN echo 'deb http://download.opensuse.org/repositories/security:/zeek/xUbuntu_24.04/ /' >> /etc/apt/sources.list.d/security:zeek.list ; \
curl -fsSL "https://download.opensuse.org/repositories/security:zeek/xUbuntu_24.04/Release.key" | gpg --dearmor | tee /etc/apt/trusted.gpg.d/security_zeek.gpg > /dev/null ; \
apt update ; apt install zeek-6.0 -y

RUN nix-channel --add https://nixos.org/channels/nixpkgs-unstable nixpkgs \
&& echo "filter-syscalls = false" >> /etc/nix/nix.conf \
&& nix-channel --update \
&& nix-env --install --attr nixpkgs.bulk_extractor nixpkgs.radare2

RUN ln -sf /usr/bin/python3 /usr/bin/python \
&& curl -fsSL https://raw.githubusercontent.com/python-poetry/install.python-poetry.org/main/install-poetry.py | python3

ENV PATH="/nix/var/nix/profiles/default/bin:/root/.local/bin:$PATH"

RUN echo "export PATH=$PATH" >> ~/.bashrc

COPY . /deject

RUN poetry install --compile

ENTRYPOINT ["poetry","run","deject"]
