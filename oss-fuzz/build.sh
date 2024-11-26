#!/bin/bash

set -e

mkdir -p ~/.gradle
echo "auto.include.git.dirs=$(pwd)" >> ~/.gradle/gradle.properties

cd micronaut-fuzzing

# bug in micronaut-build
mkdir -p checkouts
touch checkouts/catalog-micronaut-core.sha1

./gradlew micronaut-fuzzing-tests:prepareClusterFuzz
