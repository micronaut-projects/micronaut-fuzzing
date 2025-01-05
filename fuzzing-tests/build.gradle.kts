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

group = "io.micronaut.fuzzing"

dependencies {
    implementation(mn.micronaut.http.server.netty)
    implementation(mn.micronaut.jackson.databind)
    implementation(mn.reactor)

    implementation("ch.qos.logback:logback-classic:1.4.14")

    implementation(projects.micronautFuzzingApi)

    annotationProcessor(mn.micronaut.inject.java)
    annotationProcessor(projects.micronautFuzzingAnnotationProcessor)

    testImplementation("org.junit.jupiter:junit-jupiter-engine:5.11.4")
    testImplementation("org.junit.jupiter:junit-jupiter-params:5.11.4")
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
}

tasks.named<JazzerTask>("jazzer") {
    // todo: fetch on-demand from gh releases
    jazzerBinary.set(File("/home/yawkat/bin/jazzer/0.22.1/jazzer"))
    targets.set(listOf(
        //"io.micronaut.fuzzing.toml.TomlTarget",
        //"io.micronaut.fuzzing.http.HttpTarget",
        "io.micronaut.fuzzing.http.EmbeddedHttpTarget",
        //"io.micronaut.fuzzing.http.MediaTypeTarget",
        //"io.netty.handler.HttpRequestDecoderFuzzer"
    ))
    jvmArgs.set(listOf(
        "-Xmx512M",
        "-Dio.netty.leakDetection.targetRecords=100",
        "-XX:+ExitOnOutOfMemoryError",
        "-XX:+HeapDumpOnOutOfMemoryError",
    ))
    rssLimitMb.set(8192)
    instrumentationIncludes.set(listOf("io.micronaut.**", "io.netty.**"))
    //forks.set(8)
    //corpus.set(File("/home/yawkat/dev/scratch/go-fuzz-corpus/httpreq/corpus"))
    //minimizeCrashFile.set(File("crash-161cd5ffd4f8b5b5d9a7e7f19784ac446343c142"))
    maxTotalTime.set(Duration.ofHours(2))
    //maxTotalTime.set(Duration.ofSeconds(10))
    coverageDumpFile.set(layout.buildDirectory.file("cov-report.exec"))
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
