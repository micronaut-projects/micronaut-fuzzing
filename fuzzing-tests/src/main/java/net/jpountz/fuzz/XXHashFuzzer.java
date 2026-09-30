/*
 * Copyright 2017-2026 original authors
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 */
package net.jpountz.fuzz;

import com.code_intelligence.jazzer.api.FuzzedDataProvider;
import io.micronaut.fuzzing.FlagAppender;
import io.micronaut.fuzzing.FuzzTarget;
import io.micronaut.fuzzing.runner.LocalJazzerRunner;
import io.netty.buffer.ByteBuf;
import io.netty.util.LeakPresenceDetector;
import net.jpountz.xxhash.StreamingXXHash32;
import net.jpountz.xxhash.StreamingXXHash64;
import net.jpountz.xxhash.XXHashFactory;

@FuzzTarget
public final class XXHashFuzzer {
    private XXHashFuzzer() {
    }

    public static void fuzzerTestOneInput(FuzzedDataProvider data) {
        byte[] input = data.consumeBytes(Lz4ByteBufFuzzingSupport.MAX_INPUT_SIZE);
        int offset = data.consumeInt(-1, input.length + 1);
        int length = data.consumeInt(-1, input.length + 1);
        int seed32 = data.consumeInt();
        long seed64 = data.consumeLong();
        ByteBuf buffer = Lz4ByteBufFuzzingSupport.buffer(input);
        try {
            XXHashFactory factory = XXHashFactory.fastestInstance();
            try {
                byte[] selected = new byte[Math.max(length, 0)];
                buffer.getBytes(offset, selected, 0, length);
                int hash = factory.hash32().hash(selected, 0, length, seed32);
                try (StreamingXXHash32 streaming = factory.newStreamingHash32(seed32)) {
                    streaming.update(selected, 0, length);
                    if (hash != streaming.getValue()) {
                        throw new AssertionError("XXHash32 values differ");
                    }
                }
                long hash64 = factory.hash64().hash(selected, 0, length, seed64);
                try (StreamingXXHash64 streaming = factory.newStreamingHash64(seed64)) {
                    streaming.update(selected, 0, length);
                    if (hash64 != streaming.getValue()) {
                        throw new AssertionError("XXHash64 values differ");
                    }
                }
            } catch (IllegalArgumentException | IndexOutOfBoundsException ignored) {
                // Invalid offset and length combinations must fail safely.
            }
        } finally {
            buffer.release();
        }
        LeakPresenceDetector.check();
        FlagAppender.checkTriggered();
    }

    public static void main(String[] args) {
        LocalJazzerRunner.create(XXHashFuzzer.class).fuzz();
    }
}
