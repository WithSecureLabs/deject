#!/bin/bash
sudo apt update && sudo apt upgrade -y && sudo apt install autoconf automake flex gcc g++ libssl-dev zlib1g-dev libexpat1-dev libxml2-dev dpkg-dev openssl patch wget bison git libewf-dev -y
git clone --recursive https://github.com/simsong/bulk_extractor.git
pushd bulk_extractor && ./bootstrap.sh && ./configure && make 
popd
mv bulk_extractor/src/bulk_extractor bin/
sudo apt update ; apt upgrade -y
sudo apt install git curl build-essential libffi-dev python3 python3-dev python3-pip libtool libssl-dev swig libfuzzy-dev libexpat1 -y
echo 'deb http://download.opensuse.org/repositories/security:/zeek/xUbuntu_22.04/ /' | sudo tee /etc/apt/sources.list.d/security:zeek.list
curl -fsSL https://download.opensuse.org/repositories/security:zeek/xUbuntu_22.04/Release.key | sudo gpg --dearmor > /etc/apt/trusted.gpg.d/security_zeek.gpg
sudo apt update ; sudo apt install zeek -y
curl -fsSL https://github.com/radareorg/radare2/releases/download/5.8.8/radare2_5.8.8_amd64.deb -o radare2_5.8.8_amd64.deb
sudo dpkg -i radare2_5.8.8_amd64.deb
curl -fsSL https://raw.githubusercontent.com/python-poetry/install.python-poetry.org/main/install-poetry.py | python3
ln -s /opt/zeek/bin/zeek bin/zeek
poetry install --compile