plugins {
    id("java-gradle-plugin")
}

repositories {
    mavenCentral()
}

dependencies {
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
