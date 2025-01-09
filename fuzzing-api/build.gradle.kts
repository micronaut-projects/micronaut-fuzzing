plugins {
    id("io.micronaut.build.internal.fuzzing-module")
}

dependencies {
    api(libs.managed.jazzer.api)
    compileOnly(mn.micronaut.core)

    testImplementation(mnTest.junit.jupiter.engine)
    testImplementation(mnTest.junit.jupiter.params)
}
