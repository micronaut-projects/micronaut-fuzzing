#!/bin/bash

set -e

cd micronaut-fuzzing
./gradlew fuzzing-tests:prepareClusterFuzz
