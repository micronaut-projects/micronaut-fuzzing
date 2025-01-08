pluginManagement {
    includeBuild("../build-logic")
}

rootProject.name = "micronaut-jazzer-plugin"

plugins {
    id("io.micronaut.build.shared.settings") version "7.3.2"
}

enableFeaturePreview("TYPESAFE_PROJECT_ACCESSORS")

micronautBuild {
    useStandardizedProjectNames = true
    importMicronautCatalog()
}

val secring = File(settingsDir, "../secring.gpg").normalize()
if (secring.exists()) {
    val target = File(settingsDir, "secring.gpg")
    if (!target.exists()) {
        secring.copyTo(target)
    }
}
