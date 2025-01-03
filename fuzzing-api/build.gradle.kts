plugins {
    id("io.micronaut.build.internal.fuzzing-module")
}

dependencies {
    api(libs.managed.jazzer.api)
}
