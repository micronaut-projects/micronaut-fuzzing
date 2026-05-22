pluginManagement {
    includeBuild("../build-logic")
}

rootProject.name = "micronaut-jazzer-plugin"

plugins {
    id("io.micronaut.build.shared.settings") version "8.0.0-M9"
}

enableFeaturePreview("TYPESAFE_PROJECT_ACCESSORS")
micronautBuild {
    useStandardizedProjectNames = true
    importMicronautCatalog()
    importMicronautCatalogFromGAV("io.micronaut:micronaut-core-bom:5.0.0")
}

val secring = File(settingsDir, "../secring.gpg").normalize()
if (secring.exists()) {
    val target = File(settingsDir, "secring.gpg")
    if (!target.exists()) {
        secring.copyTo(target)
    }
}
