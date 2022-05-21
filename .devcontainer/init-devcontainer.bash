#!/bin/bash
apt update
apt install -y entr
pip install -U pip
pip install fabric pre-commit
fab develop
pre-commit install
