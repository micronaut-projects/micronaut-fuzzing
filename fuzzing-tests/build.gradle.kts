import io.micronaut.fuzzing.jazzer.JazzerTask
import io.micronaut.fuzzing.jazzer.PrepareClusterFuzzTask
import java.time.Duration

plugins {
    id("io.micronaut.build.internal.fuzzing-module")
    id("io.micronaut.fuzzing.jazzer")
}

repositories {
    mavenCentral()
}

micronautBuild {
    javaVersion.set(21)
}

tasks.withType<JavaCompile> {
    options.compilerArgs.add("--enable-preview")
    options.release.set(21)
}

tasks.withType<Test>() {
    jvmArgs("--enable-preview")
}

group = "io.micronaut.fuzzing"

dependencies {
    implementation(mn.micronaut.http.server.netty)
    implementation(mn.micronaut.jackson.databind)
    implementation(mn.reactor)

    implementation(mnLogging.logback.classic)

    implementation(projects.micronautFuzzingApi)
    implementation(projects.micronautFuzzingRunner)

    runtimeOnly("com.aayushatharva.brotli4j:native-linux-x86_64:1.18.0")
    runtimeOnly("com.aayushatharva.brotli4j:brotli4j:1.18.0")
    runtimeOnly("com.github.jponge:lzma-java:1.3")
    runtimeOnly("com.github.luben:zstd-jni:1.5.7-4")
    runtimeOnly("com.jcraft:jzlib:1.1.3")
    runtimeOnly("com.ning:compress-lzf:1.1.2")
    runtimeOnly("org.lz4:lz4-java:1.8.0")
    runtimeOnly("org.bouncycastle:bcpkix-jdk18on:1.80")
    implementation("io.netty:netty-codec-xml")

    annotationProcessor(mn.micronaut.inject.java)
    annotationProcessor(projects.micronautFuzzingAnnotationProcessor)

    testImplementation(mnTest.junit.jupiter.engine)
    testImplementation(mnTest.junit.jupiter.params)
    testImplementation(mn.micronaut.http.client)
    testImplementation(mnTest.micronaut.test.junit5)
    testAnnotationProcessor(mn.micronaut.inject.java)
}

tasks.withType<PrepareClusterFuzzTask> {
    introspector {
        includes = listOf("io.micronaut.*")
        excludes = listOf(
            "io.micronaut.context.*",
            "io.micronaut.core.util.clhm.ConcurrentLinkedHashMap*",
            "io.micronaut.core.util.clhm.ConcurrentLinkedHashMap*",
        )
    }
    jvmArgs = listOf(
        "-XX:+UseParallelGC",
        "-XX:GCTimeLimit=80", // avoid gc thrashing
        "-Xmx512M",
        "-XX:MaxDirectMemorySize=256M",
        "-Dio.netty.noUnsafe=true",
        "-Dio.netty.customResourceLeakDetector=io.netty.util.LeakPresenceDetector",
        "-Dio.netty.leakDetection.targetRecords=0",
        "-Dtrack-current-test-case=false",
        "-XX:+ExitOnOutOfMemoryError",
        "--enable-preview"
    )
    javaHome.set("/usr/lib/jvm/java-21-openjdk-amd64")
}

tasks.named<JazzerTask>("jazzer") {
    val collectJfr = true

    targets.set(listOf(
        //"io.micronaut.fuzzing.toml.TomlTarget",
        //"io.micronaut.fuzzing.http.HttpTarget",
        "io.micronaut.fuzzing.http.EmbeddedHttpTarget",
        //"io.micronaut.fuzzing.http.MediaTypeTarget",
        //"io.netty.handler.HttpRequestDecoderFuzzer"
    ))
    val jvmArgs = mutableListOf(
        "-Xmx512M",
        "-XX:MaxDirectMemorySize=256M",
        "-Dio.netty.noUnsafe=true",
        "-Dio.netty.customResourceLeakDetector=io.netty.util.LeakPresenceDetector",
        "-Dio.netty.util.LeakPresenceDetector.trackCreationStack=true",
        "-Dio.netty.leakDetection.targetRecords=100",
        "-XX:+ExitOnOutOfMemoryError",
        "-XX:+HeapDumpOnOutOfMemoryError",
        "--enable-preview"
    )
    if (collectJfr) {
        jvmArgs += listOf("-XX:+FlightRecorder", "-XX:StartFlightRecording=settings=cpu-times.jfc,filename=build/cpu-times.jfr")
    }
    this.jvmArgs.set(jvmArgs)
    rssLimitMb.set(8192)
    instrumentationIncludes.set(listOf("io.micronaut.**", "io.netty.**"))
    //minimizeCrashFile.set(File("minimized-from-84bb018a9cb013e56e2fe5689989968b0a685ba6"))
    maxTotalTime.set(if (collectJfr) Duration.ofMinutes(2) else Duration.ofHours(2))
    //coverageDumpFile.set(layout.buildDirectory.file("cov-report.exec"))
}

val jazzerReportDir = layout.buildDirectory.dir("jacocoJazzerHtml")

tasks.create("jacocoJazzerReport", JacocoReport::class.java) {
    executionData(layout.buildDirectory.file("cov-report.exec"))
    classDirectories.from(files(sourceSets.main.get().runtimeClasspath.files.map { dir ->
        if (dir.isFile) {
            zipTree(dir).matching { exclude("META-INF/**") }
        } else {
            fileTree(dir) { exclude("META-INF/**") }
        }
    }))
    reports {
        xml.required = false
        csv.required = false
        html.required = true
        html.outputLocation = jazzerReportDir
    }
    dependsOn("jazzer")
}

tasks.create("jacocoJazzerReportTar", Tar::class.java) {
    archiveFileName = "coverage-report.tar.bz2"
    compression = Compression.BZIP2
    from(jazzerReportDir)
    dependsOn("jacocoJazzerReport")
}
