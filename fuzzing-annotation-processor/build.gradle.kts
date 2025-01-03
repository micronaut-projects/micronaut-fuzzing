plugins {
    id("io.micronaut.build.internal.fuzzing-module")
}

dependencies {
    implementation(mn.micronaut.core.processor)
    implementation(mn.jackson.databind)
    implementation(projects.micronautFuzzingApi)

    testImplementation(mn.micronaut.inject.java.test)
}
