pluginManagement {
    repositories {
        gradlePluginPortal()
        mavenCentral()
    }
    includeBuild("build-logic")
    includeBuild("jazzer-plugin") {
        name = "micronaut-jazzer-plugin"
    }
}

plugins {
    id("io.micronaut.build.shared.settings") version "7.3.2"
}

rootProject.name = "fuzzing-parent"

include("fuzzing-annotation-processor")
include("fuzzing-api")
include("fuzzing-runner")
include("fuzzing-tests")

enableFeaturePreview("TYPESAFE_PROJECT_ACCESSORS")

micronautBuild {
    useStandardizedProjectNames = true

    importMicronautCatalog()

    if (providers.environmentVariable("OSSFUZZ_MICRONAUT_BRANCH").isPresent) {
        requiresDevelopmentVersion("micronaut-core", providers.environmentVariable("OSSFUZZ_MICRONAUT_BRANCH").get())
    }
}
