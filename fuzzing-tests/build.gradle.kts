plugins {
    id("io.micronaut.build.internal.module")
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

micronautBuild {
    sourceCompatibility.set("17")
    targetCompatibility.set("17")
}

tasks.named<io.micronaut.internal.jazzer.JazzerTask>("jazzer") {
    // todo: fetch on-demand from gh releases
    jazzerBinary.set(File("/home/yawkat/dev/scratch/jazzer/jazzer"))
    targetClasses.set(listOf(
        //"io.micronaut.fuzzing.toml.TomlTarget",
        //"io.micronaut.fuzzing.http.HttpTarget",
        "io.micronaut.fuzzing.http.EmbeddedHttpTarget",
    ))
    jvmArgs.set(listOf(
        "-Xmx512M",
        "-Dio.netty.leakDetection.level=paranoid",
        "-Dio.netty.leakDetection.targetRecords=100"
    ))
    instrumentationIncludes.set(listOf("io.micronaut.**"))
    //forks.set(8)
    // todo: store in repo
    corpus.set(File("/home/yawkat/dev/scratch/go-fuzz-corpus/httpreq/corpus"))
    //minimizeCrashFile.set(File("crash-cca31614e76829eed48909625efe6b36c150efbe"))
}
