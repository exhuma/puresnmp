#!/bin/bash
# -----------------------------------------------------------------------------
# This script is executed in the root-folder (as non-root user) of the project
# when the container is created using the VS-Code Remote-Development extension.
# -----------------------------------------------------------------------------
fab develop
pre-commit install
