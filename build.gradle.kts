plugins {
    id("io.micronaut.build.internal.docs")
    id("io.micronaut.build.internal.quality-reporting")
}

// These tasks are used in the release workflow, but the jazzer plugin is an included build
listOf("publishAllPublicationsToBuildRepository", "publishToSonatype", "closeAndReleaseSonatypeStagingRepository").forEach {t ->
    if (tasks.names.find { it == t } == null) {
        tasks.register(t) {
            dependsOn(gradle.includedBuilds.find { it.name == "micronaut-jazzer-plugin" }?.task(":$t"))
        }
    } else {
        tasks.named(t) {
            dependsOn(gradle.includedBuilds.find { it.name == "micronaut-jazzer-plugin" }?.task(":$t"))
        }
    }
}
