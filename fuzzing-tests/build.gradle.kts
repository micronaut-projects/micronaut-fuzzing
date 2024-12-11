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
    //api(mn.micronaut.json.core)

    implementation(mn.micronaut.http.server.netty)
    implementation(mn.micronaut.jackson.databind)
    implementation(mn.reactor)

    implementation("ch.qos.logback:logback-classic:1.4.14")

    implementation("com.code-intelligence:jazzer-api:0.22.1")
}

tasks.named<PrepareClusterFuzzTask>("prepareClusterFuzz") {
    targetClasses.set(listOf(
        //"io.micronaut.fuzzing.http.HttpTarget",
        "io.micronaut.fuzzing.http.EmbeddedHttpTarget",
        "io.micronaut.fuzzing.http.MediaTypeTarget"
    ))
}

tasks.named<JazzerTask>("jazzer") {
    // todo: fetch on-demand from gh releases
    jazzerBinary.set(File("/home/yawkat/bin/jazzer/0.22.1/jazzer"))
    targetClasses.set(listOf(
        //"io.micronaut.fuzzing.toml.TomlTarget",
        //"io.micronaut.fuzzing.http.HttpTarget",
        "io.micronaut.fuzzing.http.EmbeddedHttpTarget",
        //"io.micronaut.fuzzing.http.MediaTypeTarget",
        //"io.netty.handler.HttpRequestDecoderFuzzer"
    ))
    jvmArgs.set(listOf(
        "-Xmx512M",
        "-Dio.netty.leakDetection.level=paranoid",
        "-Dio.netty.leakDetection.targetRecords=100",
        "-XX:+ExitOnOutOfMemoryError",
        "-XX:+HeapDumpOnOutOfMemoryError",
    ))
    rssLimitMb.set(8192)
    instrumentationIncludes.set(listOf("io.micronaut.**", "io.netty.**"))
    //forks.set(8)
    // todo: store in repo
    corpus.set(File("/home/yawkat/dev/scratch/go-fuzz-corpus/httpreq/corpus"))
    //minimizeCrashFile.set(File("crash-f8c58ba04554c9659bc85f1e750334a5138396e2"))
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
