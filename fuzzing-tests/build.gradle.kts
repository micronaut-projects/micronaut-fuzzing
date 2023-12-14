plugins {
    id("io.micronaut.build.internal.fuzzing-module")
    id("io.micronaut.internal.jazzer")
}

repositories {
    mavenCentral()
    mavenLocal() // TODO
}

group = "io.micronaut.fuzzing"

dependencies {
    //api(mn.micronaut.json.core)

    implementation("io.micronaut:micronaut-http-server-netty:3.4.0-SNAPSHOT")
    implementation("io.projectreactor:reactor-core:3.4.14")

    implementation("ch.qos.logback:logback-classic")

    implementation("com.code-intelligence:jazzer-api:0.10.0")

    implementation("io.netty:netty-common:4.1.75.Final-SNAPSHOT")
}

tasks.named<io.micronaut.internal.jazzer.JazzerTask>("jazzer") {
    // todo: fetch on-demand from gh releases
    jazzerBinary.set(File("/home/yawkat/Downloads/jazzer"))
    targetClasses.set(listOf(
        //"io.micronaut.fuzzing.toml.TomlTarget",
        //"io.micronaut.fuzzing.http.HttpTarget",
        //"io.micronaut.fuzzing.http.EmbeddedHttpTarget",
        //"io.micronaut.fuzzing.CastTarget",
        //"io.micronaut.fuzzing.json.JsonCounterTarget",
        "io.micronaut.fuzzing.json.JsonCounterSplitTarget",
        //"io.micronaut.fuzzing.json.JsonCounterSplitUnwrappedTarget",
    ))
    jvmArgs.set(listOf(
        "-Xmx512M",
    ))
    instrumentationIncludes.set(listOf("io.micronaut.fuzzing.json.**", "com.fasterxml.jackson.core.json.**"))
    forks.set(16)
    // todo: store in repo
    //corpus.set(File("/home/yawkat/dev/scratch/go-fuzz-corpus/httpreq/corpus"))
    //corpus.set(File("../compile-corpus"))
    //onlyAscii.set(true)
    //minimizeCrashFile.set(File("crash-cca31614e76829eed48909625efe6b36c150efbe"))
}
