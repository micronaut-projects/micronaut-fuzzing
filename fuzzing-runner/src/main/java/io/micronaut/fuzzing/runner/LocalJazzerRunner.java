/*
 * Copyright 2017-2025 original authors
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * https://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package io.micronaut.fuzzing.runner;

import com.code_intelligence.jazzer.Jazzer;
import com.code_intelligence.jazzer.agent.AgentInstaller;
import com.code_intelligence.jazzer.api.FuzzedDataProvider;
import com.code_intelligence.jazzer.driver.FuzzedDataProviderImpl;
import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.ObjectMapper;
import io.micronaut.core.annotation.NonNull;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.io.UncheckedIOException;
import java.lang.invoke.MethodHandles;
import java.lang.invoke.MethodType;
import java.net.URL;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.Enumeration;
import java.util.List;

/**
 * This class can be used as a convenient runner for {@link io.micronaut.fuzzing.FuzzTarget}s. For
 * example:
 *
 * <pre>{@code
 * @FuzzTarget
 * public class Example {
 *     public static void fuzzerTestOneInput(byte[] input) {
 *         ...
 *     }
 *
 *     public static void main(String[] args) {
 *         LocalJazzerRunner.create(Example.class).fuzz();
 *     }
 * }
 * }</pre>
 *
 * Running the main method will run the fuzzer.
 */
public final class LocalJazzerRunner {
    private static final ObjectMapper MAPPER = new ObjectMapper();

    private final Class<?> targetClass;
    private final DefinedFuzzTarget target;

    private LocalJazzerRunner(Class<?> targetClass, DefinedFuzzTarget target) {
        this.targetClass = targetClass;
        this.target = target;
    }

    /**
     * Create a runner for the given target class.
     *
     * @param fuzzTarget The fuzz target class. Must be annotated with {@link io.micronaut.fuzzing.FuzzTarget}.
     * @return The runner
     */
    @NonNull
    public static LocalJazzerRunner create(@NonNull Class<?> fuzzTarget) {
        return new LocalJazzerRunner(fuzzTarget, findDefinition(fuzzTarget, fuzzTarget));
    }

    private void writeDictionary(OutputStream out) throws IOException {
        target.writeStaticDictionary(out);
        if (target.dictionaryResources() != null) {
            for (String r : target.dictionaryResources()) {
                Enumeration<URL> urls = LocalJazzerRunner.class.getClassLoader().getResources(r);
                if (!urls.hasMoreElements()) {
                    throw new IllegalStateException("Dictionary resource " + r + " not found");
                }
                do {
                    DefinedFuzzTarget.writeResourceDictionaryPrefix(out, r);
                    try (InputStream in = urls.nextElement().openStream()) {
                        in.transferTo(out);
                    }
                    out.write('\n');
                } while (urls.hasMoreElements());
            }
        }
    }

    /**
     * Run the normal jazzer fuzzer.
     */
    public void fuzz() {
        Path dict = null;
        try {
            List<String> args = new ArrayList<>();
            if (target.dictionaryResources() != null || target.dictionary() != null) {
                dict = Files.createTempFile("fuzzing-", ".dict");
                try (OutputStream out = Files.newOutputStream(dict)) {
                    writeDictionary(out);
                }
                args.add("-dict=" + dict.toAbsolutePath());
            }
            args.add("--target_class=" + target.targetClass());

            Jazzer.main(args.toArray(new String[0]));
        } catch (IOException e) {
            throw new UncheckedIOException(e);
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
        } finally {
            if (dict != null) {
                try {
                    Files.deleteIfExists(dict);
                } catch (IOException ignored) {
                }
            }
        }
    }

    /**
     * Reproduce a crash with the given data in this JVM, for easy debugging.
     *
     * @param path Path to the data that leads to the crash
     * @see #reproduce(byte[])
     */
    public void reproduce(@NonNull Path path) {
        try {
            reproduce(Files.readAllBytes(path));
        } catch (IOException e) {
            throw new UncheckedIOException(e);
        }
    }

    /**
     * Reproduce a crash with the given data in this JVM, for easy debugging.
     *
     * @param data The data that leads to the crash
     */
    public void reproduce(byte @NonNull [] data) {
        // this method somewhat based on jazzer's Replayer.java

        ClassLoader.getSystemClassLoader().setDefaultAssertionStatus(true);
        // this is needed to get some bootstrap classes (UnsafeProvider), but we don't actually need to instrument anything
        AgentInstaller.install(false);
        try {
            try {
                MethodHandles.lookup().findStatic(targetClass, "fuzzerInitialize", MethodType.methodType(void.class))
                    .invoke();
            } catch (NoSuchMethodException ignored) {
            }
            try {
                MethodHandles.lookup().findStatic(targetClass, "fuzzerTestOneInput", MethodType.methodType(void.class, byte[].class))
                    .invokeExact(data);
            } catch (NoSuchMethodException e) {
                try {
                    MethodHandles.lookup().findStatic(targetClass, "fuzzerTestOneInput", MethodType.methodType(void.class, FuzzedDataProvider.class))
                        .invokeExact((FuzzedDataProvider) FuzzedDataProviderImpl.withJavaData(data));
                } catch (NoSuchMethodException f) {
                    throw new IllegalArgumentException("Found no fuzzerTestOneInput method with appropriate argument type on " + targetClass, f);
                }
            }
        } catch (RuntimeException | Error e) {
            throw e;
        } catch (Throwable e) {
            throw new RuntimeException(e);
        }
    }

    private static DefinedFuzzTarget findDefinition(@NonNull Class<?> ctx, @NonNull Class<?> fuzzTarget) {
        try (InputStream stream = LocalJazzerRunner.class.getResourceAsStream("/META-INF/" + DefinedFuzzTarget.DIRECTORY + "/" + ctx.getName() + ".json")) {
            if (stream == null) {
                if (ctx.getEnclosingClass() == null) {
                    throw new IllegalArgumentException("No fuzz target metadata found for " + fuzzTarget.getName() + ". Please make sure the target is annotated with @FuzzTarget, and that the annotation processor is applied.");
                }
                return findDefinition(ctx.getEnclosingClass(), fuzzTarget);
            }

            List<DefinedFuzzTarget> available = MAPPER.readValue(stream, new TypeReference<>() {
            });
            for (DefinedFuzzTarget target : available) {
                if (target.targetClass().equals(fuzzTarget.getName())) {
                    return target;
                }
            }
            throw new IllegalArgumentException("No fuzz target metadata found for " + fuzzTarget.getName() + ", but other metadata is present. Please make sure the target is annotated with @FuzzTarget.");
        } catch (IOException e) {
            throw new UncheckedIOException(e);
        }
    }
}
