plugins {
    id("io.micronaut.build.internal.fuzzing-module")
    id("io.micronaut.build.internal.fuzzing-model")
}

dependencies {
    implementation(libs.managed.jazzer.standalone)
    implementation(mn.jackson.databind)
    implementation(projects.micronautFuzzingApi)
    compileOnly(mn.micronaut.core)
}

tasks {
    generateModel {
        packageName = "io.micronaut.fuzzing.runner"
    }
}
