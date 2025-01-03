rootProject.name = "jazzer-plugin"

plugins {
    id("io.micronaut.build.shared.settings") version "7.3.0"
}

enableFeaturePreview("TYPESAFE_PROJECT_ACCESSORS")

configure<io.micronaut.build.MicronautBuildSettingsExtension> {
    useStandardizedProjectNames = false
    importMicronautCatalog()
}
