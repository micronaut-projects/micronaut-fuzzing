#!/bin/bash

set -e

mkdir -p ~/.gradle
echo "auto.include.git.dirs=$(pwd)" >> ~/.gradle/gradle.properties

cd micronaut-fuzzing
./gradlew micronaut-fuzzing-tests:prepareClusterFuzz
