package io.micronaut.fuzzing.processor;

import java.util.List;

// TODO: this is symlinked to the plugin project... find a better way to share it
public record DefinedFuzzTarget(
    String targetClass,
    List<String> dictionary,
    List<String> dictionaryResources,
    boolean enableImplicitly
) {
    public static final String DIRECTORY = "io.micronaut.fuzzing.fuzz-targets";
}
