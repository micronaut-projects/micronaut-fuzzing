import io.micronaut.fuzzing.jazzer.JazzerTask
import io.micronaut.fuzzing.jazzer.PrepareClusterFuzzTask
import io.micronaut.fuzzing.jazzer.JazzerRegressionTask
import java.time.Duration

plugins {
    id("io.micronaut.build.internal.fuzzing-module")
    id("io.micronaut.fuzzing.jazzer")
}

repositories {
    mavenCentral()
}

val ossFuzzJacoco by configurations.creating

micronautBuild {
    javaVersion.set(25)
}

tasks.withType<JavaCompile> {
    options.compilerArgs.add("--enable-preview")
    options.release.set(25)
}

tasks.withType<Test>() {
    jvmArgs("--enable-preview")
    systemProperty("io.netty.customResourceLeakDetector", "io.netty.util.LeakPresenceDetector")
}

tasks.named<Test>("test") {
    exclude("io/micronaut/fuzzing/sanitizer/SanitizerTransformerTest.class")
    exclude("io/netty/handler/codec/base64/Base64EncoderFuzzerTest.class")
    exclude("io/netty/handler/codec/compression/BrotliEncoderFuzzerTest.class")
    exclude("io/netty/handler/codec/string/StringEncoderFuzzerTest.class")
    exclude("io/netty/handler/codec/http/websocketx/WebSocketFrameAggregatorFuzzerTest.class")
    exclude("io/netty/handler/codec/http2/CleartextHttp2ServerUpgradeHandlerFuzzerTest.class")
    exclude("io/netty/handler/codec/http2/Http2ConnectionHandlerFuzzerTest.class")
}

val nettyFuzzerTest by tasks.registering(Test::class) {
    description = "Runs Netty fuzzer smoke tests in isolated JVMs with leak detection."
    group = LifecycleBasePlugin.VERIFICATION_GROUP

    testClassesDirs = sourceSets.test.get().output.classesDirs
    classpath = sourceSets.test.get().runtimeClasspath

    include("io/netty/handler/codec/http/websocketx/WebSocketFrameAggregatorFuzzerTest.class")
    include("io/netty/handler/codec/http2/CleartextHttp2ServerUpgradeHandlerFuzzerTest.class")
    include("io/netty/handler/codec/http2/Http2ConnectionHandlerFuzzerTest.class")
    include("io/netty/handler/codec/base64/Base64EncoderFuzzerTest.class")
    include("io/netty/handler/codec/compression/BrotliEncoderFuzzerTest.class")
    include("io/netty/handler/codec/string/StringEncoderFuzzerTest.class")

    shouldRunAfter(tasks.named("test"))
    forkEvery = 1
    jvmArgs("-Dio.netty.customResourceLeakDetector=io.netty.util.LeakPresenceDetector")

    extensions.configure<JacocoTaskExtension> {
        isEnabled = false
    }
    doFirst {
        jvmArgumentProviders.removeAll { it.javaClass.name.contains("Jacoco") }
    }
}

val lz4FrameDecoderRegression by tasks.registering(JazzerRegressionTask::class) {
    description = "Runs the LZ4 frame decoder OSS-Fuzz regression input."
    group = LifecycleBasePlugin.VERIFICATION_GROUP

    targets.set(setOf("io.netty.handler.codec.compression.Lz4FrameDecoderFuzzer"))
    jvmArgs.set(listOf(
        "-Dio.netty.customResourceLeakDetector=io.netty.util.LeakPresenceDetector",
        "-Dio.netty.leakDetection.targetRecords=0",
        "--enable-preview"
    ))
    base64RegressionInputs.put("oss-fuzz-4644981624340480", """
        TFo0QmxvY2spggAAAP4AAAAAAAoKU0VQO1NFUHRTRVA7U0VQdKlTRVB0S0NBTEVOJ0RBUgB8RVBT
        RVBTRVBTRVBTRVBNS0FDVElWSVRZU0VQU0VQU0VQUHJBUgB8RWFnbWFTRVBTRVBTRVBTRSpTRVBT
        RVBDb25uZWN0aW9uOlNFUFNFUFNFUFNFUFNFUFNFUFNFUFNFUFNTRVBTUFNFUFNFUFNFUFNFUFNF
        UFNFKlNFUFNFUFNFUFNFUFNFUFNFU0VQU0VQU0VQU0VQU0VQU0VQU0VQU0VQU0VTRVBTRVBTRVBT
        RWFkZFBTRVBTRVBTRSpTRVBTRVBTRVBTRVAAAAB8RVBTRVBTRVBTRVBTRVBTRVBTRVBTRVBTU0VQ
        U0VQU0VQU0VQPVNFUFNFUFNFKlNFUFNFUFNFUFNFUFNFUFNFUFNFUFNFUFNFUFNFUFNTRVBTUFNF
        UFNFUFNTRVBTRVBTRVBTRSpTRVBTRVBTRVBTU+FQU+NFUFNFUFNFUFNFUFNFUFNFUFNFKlNFUCNF
        UFNFUENFUFNFUFNFUFNFUFNFUFNFUFNFUFNFUFNFUFNFUFNTRVBTRVBTRVBTU0VQU0VQU0VQU0VQ
        U0VTRVBTRVBTRVBTRVBQRVBFU1NTRVBTU0VQU0VQU0VQUHJhZ21TRVBTRVBTRVBTRVBTRVBTRVBT
        RVBTRSpFUFNFUFNTRVBTRVBTRVA=
    """.trimIndent())
}

val httpClientUpgradeHandlerRegression by tasks.registering(JazzerRegressionTask::class) {
    description = "Runs the HTTP client upgrade handler OSS-Fuzz regression input."
    group = LifecycleBasePlugin.VERIFICATION_GROUP

    targets.set(setOf("io.netty.handler.codec.http.HttpClientUpgradeHandlerFuzzer"))
    jvmArgs.set(listOf(
        "-Dio.netty.customResourceLeakDetector=io.netty.util.LeakPresenceDetector",
        "-Dio.netty.leakDetection.targetRecords=0",
        "--enable-preview"
    ))
    base64RegressionInputs.put("oss-fuzz-5406620929818624", """
        SFRUUC8wLjIJMTAxIAAABA7+/7ktMQBEDQoNCgAAAAQAAAAAAAAAAUxBQkVMAAAAAAABRf8A2goA
        AAQAAAAAADAuMhwAAAAAAAAxCQEAAAAAZaXEMjE0AAAAAUX/ANoKAAAEAADMzMzMzMw5NjcyNkk=
    """.trimIndent())
}

val brotliDecoderRegression by tasks.registering(JazzerRegressionTask::class) {
    description = "Runs the Brotli decoder OSS-Fuzz regression input."
    group = LifecycleBasePlugin.VERIFICATION_GROUP

    targets.set(setOf("io.netty.handler.codec.compression.BrotliDecoderFuzzer"))
    jvmArgs.set(listOf(
        "-Dio.netty.customResourceLeakDetector=io.netty.util.LeakPresenceDetector",
        "-Dio.netty.leakDetection.targetRecords=0",
        "--enable-preview"
    ))
    base64RegressionInputs.put("oss-fuzz-5310533434933248", "A37///8A")
}

val bzip2DecoderRegression by tasks.registering(JazzerRegressionTask::class) {
    description = "Runs the Bzip2 decoder OSS-Fuzz regression input."
    group = LifecycleBasePlugin.VERIFICATION_GROUP

    targets.set(setOf("io.netty.handler.codec.compression.Bzip2DecoderFuzzer"))
    jvmArgs.set(listOf(
        "-Dio.netty.customResourceLeakDetector=io.netty.util.LeakPresenceDetector",
        "-Dio.netty.leakDetection.targetRecords=0",
        "--enable-preview"
    ))
    base64RegressionInputs.put("oss-fuzz-5399056135028736", """
        QlpoNTFBWSZTWUkAAAAAAAAAICAgICAgIAAAQlgtUmVxdWVzdGVkLVdpdGhJTkQgICAAXWphdmEv
        dXRpbC9BcnJheXMgICAgICAgICAgICAgJAkgb1QgICQgJTU0
    """.trimIndent())
}

val jsonObjectDecoderRegression by tasks.registering(JazzerRegressionTask::class) {
    description = "Runs the JSON object decoder OSS-Fuzz regression input."
    group = LifecycleBasePlugin.VERIFICATION_GROUP

    targets.set(setOf("io.netty.handler.codec.json.JsonObjectDecoderFuzzer"))
    jvmArgs.set(listOf(
        "-Dio.netty.customResourceLeakDetector=io.netty.util.LeakPresenceDetector",
        "-Dio.netty.leakDetection.targetRecords=0",
        "--enable-preview"
    ))
    base64RegressionInputs.put("oss-fuzz-5825897350103040", "fgADpg==")
}

val sniHandlerRegression by tasks.registering(JazzerRegressionTask::class) {
    description = "Runs the SNI handler OSS-Fuzz regression input."
    group = LifecycleBasePlugin.VERIFICATION_GROUP

    targets.set(setOf("io.netty.handler.ssl.SniHandlerFuzzer"))
    jvmArgs.set(listOf(
        "-Dio.netty.customResourceLeakDetector=io.netty.util.LeakPresenceDetector",
        "-Dio.netty.leakDetection.targetRecords=0",
        "--enable-preview"
    ))
    base64RegressionInputs.put("oss-fuzz-6335646063722496", """
        FgNdAScBAADNKSn///////+AgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIB/gICAYXJy
        YXmAgICAgICAgIAIgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIACOICA
        gICAgICAgICAgID//////////////////////////////////////zD///9TRVD/////////////
        //8BqwAAAAAlhQ4AAq92AAAAAAAAAAANGZgUUFNTiYlhU0VQYWFhYWFhaWFhYQAAAAAAAAAAAAAA
        AAAAAAAAAABh///////////9//////////8A/////////////////////y7/////////////////
        /////1NFUP////8eHh4eHh4eHh5FUEVQU0VQU0UAU2FQ
    """.trimIndent())
}

val sanitizerTest by tasks.registering(Test::class) {
    description = "Runs sanitizer bytecode transformation tests in an isolated JVM."
    group = LifecycleBasePlugin.VERIFICATION_GROUP

    testClassesDirs = sourceSets.test.get().output.classesDirs
    classpath = sourceSets.test.get().runtimeClasspath

    include("io/micronaut/fuzzing/sanitizer/SanitizerTransformerTest.class")
    shouldRunAfter(tasks.named("test"))

    extensions.configure<JacocoTaskExtension> {
        isEnabled = false
    }
    doFirst {
        jvmArgumentProviders.removeAll { it.javaClass.name.contains("Jacoco") }
    }
}

tasks.named("check") {
    dependsOn(sanitizerTest)
    dependsOn(nettyFuzzerTest)
    dependsOn(lz4FrameDecoderRegression)
    dependsOn(httpClientUpgradeHandlerRegression)
    dependsOn(brotliDecoderRegression)
    dependsOn(bzip2DecoderRegression)
    dependsOn(jsonObjectDecoderRegression)
    dependsOn(sniHandlerRegression)
}

group = "io.micronaut.fuzzing"

dependencies {
    ossFuzzJacoco("org.jacoco:org.jacoco.agent:0.8.15:runtime")
    ossFuzzJacoco("org.jacoco:org.jacoco.cli:0.8.15:nodeps")

    implementation(mn.micronaut.http.server.netty)
    implementation(mn.netty.contrib.multipart.core)
    implementation(mn.micronaut.jackson.databind)
    implementation(mn.jackson.databind)
    implementation(mn.reactor)

    implementation(mnLogging.logback.classic)

    implementation(projects.micronautFuzzingApi)
    implementation(projects.micronautFuzzingRunner)

    implementation(mnTest.bytebuddy)

    runtimeOnly("com.aayushatharva.brotli4j:native-linux-x86_64:1.23.0")
    implementation("com.aayushatharva.brotli4j:brotli4j:1.23.0")
    runtimeOnly("com.github.jponge:lzma-java:1.3")
    runtimeOnly("com.github.luben:zstd-jni:1.5.7-11")
    runtimeOnly("com.jcraft:jzlib:1.1.3")
    runtimeOnly("com.ning:compress-lzf:1.2.0")
    implementation("org.lz4:lz4-java:1.8.0")
    runtimeOnly("org.bouncycastle:bcpkix-jdk18on:1.84")
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
    jazzerDriver.set("micronaut_jazzer_driver")
    jazzerAgent.set("micronaut_jazzer_agent_deploy.jar")
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
    javaHome.set("\$this_dir/jdk")
    doFirst {
        project.copy {
            from(ossFuzzJacoco)
            into(outputDirectory.dir("jacoco").get().asFile)
        }
    }
    val dollar = "$"
    setupScript.set("""
        if [[ "${dollar}EXTERNAL_JAZZER_ARGS" == *"/opt/jacoco-agent.jar"* ]]; then
            jacoco_agent=$(find "${dollar}this_dir/jacoco" -maxdepth 1 -name 'org.jacoco.agent-*-runtime.jar' -print -quit)
            jacoco_cli=$(find "${dollar}this_dir/jacoco" -maxdepth 1 -name 'org.jacoco.cli-*-nodeps.jar' -print -quit)
            if [[ -z "${dollar}jacoco_agent" || -z "${dollar}jacoco_cli" ]]; then
                echo "Missing bundled JaCoCo jars in ${dollar}this_dir/jacoco" >&2
                exit 1
            fi
            cp "${dollar}jacoco_agent" "/opt/jacoco-agent.jar.${dollar}${dollar}"
            mv "/opt/jacoco-agent.jar.${dollar}${dollar}" /opt/jacoco-agent.jar
            cp "${dollar}jacoco_cli" "/opt/jacoco-cli.jar.${dollar}${dollar}"
            mv "/opt/jacoco-cli.jar.${dollar}${dollar}" /opt/jacoco-cli.jar
        fi
    """.trimIndent())
}

tasks.named<JazzerTask>("jazzer") {
    val collectJfr = true

    targets.set(listOf(
        //"io.micronaut.fuzzing.toml.TomlTarget",
        //"io.micronaut.fuzzing.http.HttpTarget",
        //"io.micronaut.fuzzing.http.EmbeddedHttpTarget",
        //"io.netty.handler.codec.base64.Base64EncoderFuzzer",
        "io.netty.handler.codec.compression.BrotliEncoderFuzzer",
        //"io.netty.handler.codec.string.StringEncoderFuzzer",
        //"io.micronaut.fuzzing.http.MediaTypeTarget",
        //"io.netty.handler.HttpRequestDecoderFuzzer"
        //"io.micronaut.fuzzing.http.UriMatchTemplateTarget",
        //"io.micronaut.fuzzing.http.TypeConversionTarget",
        //"io.micronaut.fuzzing.http.ContentNegotiationTarget",
        //"io.micronaut.fuzzing.http.MultipartTarget",
    ))
    val jvmArgs = mutableListOf(
        "-Xmx512M",
        "-XX:MaxDirectMemorySize=256M",
        "-Dio.netty.noUnsafe=true",
        "-Dio.netty.customResourceLeakDetector=io.netty.util.LeakPresenceDetector",
        //"-Dio.netty.util.LeakPresenceDetector.trackCreationStack=true",
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
    //minimizeCrashFile.set(File("minimized-from-84bb018a9cb013e56e2fe5689989968b0a685ba6"))
    maxTotalTime.set(if (collectJfr) Duration.ofMinutes(2) else Duration.ofHours(2))
    //coverageDumpFile.set(layout.buildDirectory.file("cov-report.exec"))
}

tasks.register<JazzerTask>("reproduceOssFuzz4768382317821952") {
    description = "Reproduces OSS-Fuzz testcase 4768382317821952 with EmbeddedHttpTarget."
    group = LifecycleBasePlugin.VERIFICATION_GROUP

    classpath.from(tasks.named<JazzerTask>("jazzer").map { it.classpath })
    targets.set(listOf("io.micronaut.fuzzing.http.EmbeddedHttpTarget"))
    jvmArgs.set(listOf(
        "-Xmx512M",
        "-XX:MaxDirectMemorySize=256M",
        "-Dio.netty.noUnsafe=true",
        "-Dio.netty.customResourceLeakDetector=io.netty.util.LeakPresenceDetector",
        "-Dio.netty.leakDetection.targetRecords=100",
        "-XX:+ExitOnOutOfMemoryError",
        "--enable-preview"
    ))
    rssLimitMb.set(8192)
    reproduceCrashFile.set(layout.projectDirectory.file("src/test/resources/oss-fuzz/4768382317821952"))
}
