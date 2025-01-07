import io.micronaut.build.internal.tasks.GenerateModelClasses

plugins {
    id("io.micronaut.build.internal.fuzzing-module")
    id("io.micronaut.build.internal.fuzzing-model")
}

dependencies {
    implementation(mn.micronaut.core.processor)
    implementation(mn.jackson.databind)
    implementation(projects.micronautFuzzingApi)

    testImplementation(mn.micronaut.inject.java.test)
}

tasks {
    generateModel {
        packageName = "io.micronaut.fuzzing.processor"
    }
}
