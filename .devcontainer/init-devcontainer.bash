#!/bin/bash
# -----------------------------------------------------------------------------
# This script is executed in the root-folder (as non-root user) of the project
# when the container is created using the VS-Code Remote-Development extension.
# -----------------------------------------------------------------------------
pip install --user pipx
pipx install fabric
pipx install pre-commit
pipx install docutils
fab develop
pre-commit install
