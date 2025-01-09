package io.micronaut.fuzzing.http;

import io.micronaut.fuzzing.FuzzTarget;
import io.micronaut.fuzzing.runner.LocalJazzerRunner;

import java.util.Map;

@FuzzTarget
public class EmbeddedHttp2Target extends EmbeddedHttpTarget {
    private static EmbeddedHttp2Target instance;

    EmbeddedHttp2Target(Map<String, Object> cfg) {
        super(cfg);
    }

    public static void fuzzerInitialize() {
        instance = new EmbeddedHttp2Target(Map.of(
            "micronaut.server.http-version", "2.0"
        ));
    }

    public static void fuzzerTestOneInput(byte[] input) {
        instance.run(input);
    }

    public static void fuzzerTearDown() {
        instance.close();
    }

    public static void main(String[] args) {
        LocalJazzerRunner.create(EmbeddedHttp2Target.class).fuzz();
    }
}
