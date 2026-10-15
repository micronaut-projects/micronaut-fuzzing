plugins {
    id("java-gradle-plugin")
    id("io.micronaut.build.internal.publishing")
    id("io.micronaut.build.internal.fuzzing-model")
}

repositories {
    mavenCentral()
}

val micronautVersion = file("../gradle/libs.versions.toml")
    .readLines()
    .first { it.startsWith("micronaut = ") }
    .substringAfter('"')
    .substringBefore('"')

dependencies {
    implementation(platform("io.micronaut:micronaut-core-bom:$micronautVersion"))
    implementation("tools.jackson.core:jackson-databind")
    compileOnly(mn.micronaut.core) // annotations

    testImplementation(mnTest.junit.jupiter.api)
    testImplementation(mnTest.junit.jupiter.engine)
    testRuntimeOnly("org.junit.platform:junit-platform-launcher")
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
