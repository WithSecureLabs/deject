FROM ubuntu:22.04 AS builder
RUN apt update && apt upgrade -y && DEBIAN_FRONTEND=noninteractive apt install autoconf automake flex gcc g++ libssl-dev zlib1g-dev libexpat1-dev libxml2-dev dpkg-dev openssl patch wget bison git libewf-dev -y
RUN git clone --recursive https://github.com/simsong/bulk_extractor.git
RUN cd bulk_extractor && ./bootstrap.sh && ./configure && make 

FROM ubuntu:22.04

SHELL ["/bin/bash", "-c"]

COPY . /deject

WORKDIR /deject

ENV DEBIAN_FRONTEND=noninteractive

RUN apt update ; apt upgrade -y

RUN apt install git curl build-essential libffi-dev python3 python3-dev python3-pip libtool libssl-dev swig libfuzzy-dev libewf-dev libexpat1 openssl -y

RUN echo 'deb http://download.opensuse.org/repositories/security:/zeek/xUbuntu_22.04/ /' > /etc/apt/sources.list.d/security:zeek.list

RUN curl -fsSL https://download.opensuse.org/repositories/security:zeek/xUbuntu_22.04/Release.key | gpg --dearmor > /etc/apt/trusted.gpg.d/security_zeek.gpg

RUN apt update ; apt install zeek -y

RUN ln -sf /usr/bin/python3 /usr/bin/python

RUN curl -fsSL https://github.com/radareorg/radare2/releases/download/5.8.8/radare2_5.8.8_amd64.deb -o radare2_5.8.8_amd64.deb

RUN dpkg -i radare2_5.8.8_amd64.deb

RUN curl -fsSL https://raw.githubusercontent.com/python-poetry/install.python-poetry.org/main/install-poetry.py | python3

RUN ln -s /opt/zeek/bin/zeek bin/zeek

COPY --from=builder /bulk_extractor/src/bulk_extractor /deject/bin/bulk_extractor

ENV PATH="/root/.local/bin:$PATH"

RUN echo "export PATH=$PATH" >> ~/.bashrc

RUN poetry install --compile

ENTRYPOINT ["poetry","run","deject"]
