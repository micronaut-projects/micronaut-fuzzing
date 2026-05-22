pluginManagement {
    includeBuild("../build-logic")
}

rootProject.name = "micronaut-jazzer-plugin"

plugins {
    id("io.micronaut.build.shared.settings") version "8.0.0-M9"
}

enableFeaturePreview("TYPESAFE_PROJECT_ACCESSORS")

val micronautVersion = File(settingsDir, "../gradle/libs.versions.toml")
    .readLines()
    .first { it.startsWith("micronaut = ") }
    .substringAfter('"')
    .substringBefore('"')

micronautBuild {
    useStandardizedProjectNames = true
    importMicronautCatalog()
    importMicronautCatalogFromGAV("io.micronaut:micronaut-core-bom:$micronautVersion")
}

val secring = File(settingsDir, "../secring.gpg").normalize()
if (secring.exists()) {
    val target = File(settingsDir, "secring.gpg")
    if (!target.exists()) {
        secring.copyTo(target)
    }
}
