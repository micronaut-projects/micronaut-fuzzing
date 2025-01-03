pluginManagement {
    repositories {
        gradlePluginPortal()
        mavenCentral()
    }
    includeBuild("jazzer-plugin")
}

plugins {
    id("io.micronaut.build.shared.settings") version "7.3.0"
}

rootProject.name = "fuzzing-parent"

include("fuzzing-annotation-processor")
include("fuzzing-api")
include("fuzzing-tests")

enableFeaturePreview("TYPESAFE_PROJECT_ACCESSORS")

configure<io.micronaut.build.MicronautBuildSettingsExtension> {
    useStandardizedProjectNames = true

    importMicronautCatalog()

    requiresDevelopmentVersion("micronaut-core", "4.8.x")
}
