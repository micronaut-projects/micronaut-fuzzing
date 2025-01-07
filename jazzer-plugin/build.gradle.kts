plugins {
    id("java-gradle-plugin")
    id("io.micronaut.build.internal.publishing")
}

repositories {
    mavenCentral()
}

dependencies {
    // todo: bom dependencies
    implementation("com.fasterxml.jackson.core:jackson-databind:2.18.2")

    testImplementation("org.junit.jupiter:junit-jupiter:5.11.4")
    testImplementation("org.junit.jupiter:junit-jupiter-engine:5.11.4")
}

tasks.test {
    useJUnitPlatform()
}

gradlePlugin {
    plugins {
        create("jazzer") {
            id = "io.micronaut.fuzzing.jazzer"
            implementationClass = "io.micronaut.fuzzing.jazzer.JazzerPlugin"
        }
    }
}
