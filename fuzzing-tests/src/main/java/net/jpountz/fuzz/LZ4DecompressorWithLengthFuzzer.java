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
import net.jpountz.lz4.LZ4DecompressorWithLength;
import net.jpountz.lz4.LZ4Exception;
import net.jpountz.lz4.LZ4Factory;

@FuzzTarget
public final class LZ4DecompressorWithLengthFuzzer {
    private LZ4DecompressorWithLengthFuzzer() {
    }

    public static void fuzzerTestOneInput(FuzzedDataProvider data) {
        ByteBuf input = Lz4ByteBufFuzzingSupport.buffer(data.consumeBytes(Lz4ByteBufFuzzingSupport.MAX_INPUT_SIZE));
        try {
            if (input.readableBytes() < Integer.BYTES) {
                return;
            }
            int length = LZ4DecompressorWithLength.getDecompressedLength(input.nioBuffer());
            if (length < 0 || length > Lz4ByteBufFuzzingSupport.MAX_OUTPUT_SIZE) {
                return;
            }
            ByteBuf output = Lz4ByteBufFuzzingSupport.buffer(new byte[length]);
            try {
                new LZ4DecompressorWithLength(LZ4Factory.fastestJavaInstance().safeDecompressor())
                    .decompress(input.nioBuffer(), 0, input.readableBytes(), output.nioBuffer(), 0);
            } catch (IllegalArgumentException | IndexOutOfBoundsException | LZ4Exception ignored) {
                // Malformed and truncated inputs are expected.
            } finally {
                output.release();
            }
        } finally {
            input.release();
        }
        LeakPresenceDetector.check();
        FlagAppender.checkTriggered();
    }

    public static void main(String[] args) {
        LocalJazzerRunner.create(LZ4DecompressorWithLengthFuzzer.class).fuzz();
    }
}
