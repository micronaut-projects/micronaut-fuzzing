#!/bin/bash

set -e

apt install -y openjdk-21-jdk-headless

git clone --depth=1 https://github.com/micronaut-projects/micronaut-core.git
