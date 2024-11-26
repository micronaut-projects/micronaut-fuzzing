#!/bin/bash

set -e

echo "auto.include.git.dirs=$(pwd)" >> ~/.gradle/gradle.properties

cd micronaut-fuzzing
./gradlew micronaut-fuzzing-tests:prepareClusterFuzz
