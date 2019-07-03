#!/usr/bin/env bash

. venv/bin/activate
pip3 install -U -r requirements.txt && rstcheck README.rst && cd docs && make html && cp -r _build/html/* ././../dnsdb-python-docs/  && flake8 gcpdns.py && rm -rf dist/ build/ && python3 setup.py sdist && python3 setup.py bdist_wheel

