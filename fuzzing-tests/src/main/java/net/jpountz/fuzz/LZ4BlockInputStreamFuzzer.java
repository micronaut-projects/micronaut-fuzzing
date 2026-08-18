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
import io.netty.buffer.ByteBufInputStream;
import io.netty.util.LeakPresenceDetector;
import net.jpountz.lz4.LZ4BlockInputStream;

import java.io.IOException;

@FuzzTarget
public final class LZ4BlockInputStreamFuzzer {
    private LZ4BlockInputStreamFuzzer() {
    }

    public static void fuzzerTestOneInput(FuzzedDataProvider data) {
        ByteBuf input = Lz4ByteBufFuzzingSupport.buffer(data.consumeBytes(Lz4ByteBufFuzzingSupport.MAX_INPUT_SIZE));
        try (LZ4BlockInputStream stream = new LZ4BlockInputStream(new ByteBufInputStream(input))) {
            byte[] output = new byte[256];
            int remaining = Lz4ByteBufFuzzingSupport.MAX_OUTPUT_SIZE;
            while (remaining > 0) {
                int read = stream.read(output, 0, Math.min(output.length, remaining));
                if (read < 0) {
                    return;
                }
                remaining -= read;
            }
        } catch (IOException | IllegalArgumentException | IndexOutOfBoundsException ignored) {
            // Corrupt and incomplete block headers are expected.
        } finally {
            input.release();
        }
        LeakPresenceDetector.check();
        FlagAppender.checkTriggered();
    }

    public static void main(String[] args) {
        LocalJazzerRunner.create(LZ4BlockInputStreamFuzzer.class).fuzz();
    }
}
