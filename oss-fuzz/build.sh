#!/bin/bash

set -e

export JAVA_HOME="$OUT/jdk"
JAZZER_VERSION=$(sed -n 's/^managed-jazzer = "\(.*\)"/\1/p' micronaut-fuzzing/gradle/libs.versions.toml)

curl -L -O https://corretto.aws/downloads/latest/amazon-corretto-25-x64-linux-jdk.tar.gz
mkdir -p $JAVA_HOME
tar -xz --strip-components=1 -f amazon-corretto-25-x64-linux-jdk.tar.gz --directory $JAVA_HOME
rm -rf $JAVA_HOME/jmods $JAVA_HOME/lib/src.zip

curl -fL -O "https://github.com/CodeIntelligenceTesting/jazzer/releases/download/v${JAZZER_VERSION}/jazzer-linux-x86-64.tar.gz"
rm -rf jazzer
mkdir jazzer
tar -xz -f jazzer-linux-x86-64.tar.gz --directory jazzer
cp jazzer/jazzer "$OUT/micronaut_jazzer_driver"
cp jazzer/jazzer_standalone.jar "$OUT/micronaut_jazzer_agent_deploy.jar"
chmod +x "$OUT/micronaut_jazzer_driver"

export PATH="$JAVA_HOME/bin:$PATH"

mkdir -p ~/.gradle
echo "auto.include.git.dirs=$(pwd)" >> ~/.gradle/gradle.properties

export OSSFUZZ_MICRONAUT_BRANCH=$(cd micronaut-core && git rev-parse --abbrev-ref HEAD)

cd micronaut-fuzzing

# bug in micronaut-build
mkdir -p checkouts
touch checkouts/catalog-micronaut-core.sha1

./gradlew --max-workers 2 micronaut-fuzzing-tests:prepareClusterFuzz
