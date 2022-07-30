#!/bin/bash
# -----------------------------------------------------------------------------
# This file bootstraps a devcontainer with personal preferences of the project
# author. This is *not* required for development.
# -----------------------------------------------------------------------------

set -xe
curl https://raw.githubusercontent.com/exhuma/dotfiles/master/bootstrap_devcontainer.bash | bash -
npm config set sign-git-tag true
