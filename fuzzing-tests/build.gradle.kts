plugins {
    id("io.micronaut.build.internal.fuzzing-module")
    id("io.micronaut.internal.jazzer")
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

tasks.named<io.micronaut.internal.jazzer.PrepareClusterFuzzTask>("prepareClusterFuzz") {
    agent.set(File("/home/yawkat/bin/jazzer/0.22.1/jazzer_standalone.jar"))
    targetClasses.set(listOf(
        //"io.micronaut.fuzzing.http.HttpTarget",
        "io.micronaut.fuzzing.http.EmbeddedHttpTarget",
        "io.micronaut.fuzzing.http.MediaTypeTarget"
    ))
}

tasks.named<io.micronaut.internal.jazzer.JazzerTask>("jazzer") {
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
        "-Dio.netty.leakDetection.targetRecords=100"
    ))
    //instrumentationIncludes.set(listOf("io.micronaut.**"))
    //instrumentationIncludes.set(listOf("io.netty.**"))
    //forks.set(8)
    // todo: store in repo
    corpus.set(File("/home/yawkat/dev/scratch/go-fuzz-corpus/httpreq/corpus"))
    //minimizeCrashFile.set(File("crash-cca31614e76829eed48909625efe6b36c150efbe"))
}
