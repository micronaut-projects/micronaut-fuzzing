pluginManagement {
    includeBuild("../build-logic")
}

rootProject.name = "micronaut-jazzer-plugin"

plugins {
    id("io.micronaut.build.shared.settings") version "7.3.1"
}

enableFeaturePreview("TYPESAFE_PROJECT_ACCESSORS")

micronautBuild {
    useStandardizedProjectNames = true
    importMicronautCatalog()
}
