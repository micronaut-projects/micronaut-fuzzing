rootProject.name = "micronaut-jazzer-plugin"

plugins {
    id("io.micronaut.build.shared.settings") version "7.3.1"
}

enableFeaturePreview("TYPESAFE_PROJECT_ACCESSORS")

configure<io.micronaut.build.MicronautBuildSettingsExtension> {
    useStandardizedProjectNames = false
    importMicronautCatalog()
}
