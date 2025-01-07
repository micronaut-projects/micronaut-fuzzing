plugins {
    id("java-gradle-plugin")
    id("io.micronaut.build.internal.publishing")
    id("io.micronaut.build.internal.fuzzing-model")
}

repositories {
    mavenCentral()
}

dependencies {
    implementation(mn.jackson.databind)
    compileOnly(mn.micronaut.core) // annotations

    testImplementation(mnTest.junit.jupiter.api)
    testImplementation(mnTest.junit.jupiter.engine)
}

tasks {
    test {
        useJUnitPlatform()
    }
    generateModel {
        packageName = "io.micronaut.fuzzing.model"
    }
}

gradlePlugin {
    plugins {
        create("jazzer") {
            id = "io.micronaut.fuzzing.jazzer"
            implementationClass = "io.micronaut.fuzzing.jazzer.JazzerPlugin"
        }
    }
}
