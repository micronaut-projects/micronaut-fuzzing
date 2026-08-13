/*
 * Copyright 2017-2026 original authors
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
package io.netty.handler.codec.compression;

import com.code_intelligence.jazzer.api.FuzzedDataProvider;
import io.micronaut.fuzzing.FlagAppender;
import io.micronaut.fuzzing.util.ByteSplitter;
import io.netty.buffer.ByteBuf;
import io.netty.buffer.ByteBufAllocator;
import io.netty.channel.embedded.EmbeddedChannel;
import io.netty.util.LeakPresenceDetector;

import java.io.ByteArrayOutputStream;
import java.util.Arrays;

/**
 * Shared differential fuzzing logic for legacy Netty decoders and {@link Decompressor} implementations.
 */
abstract class AbstractDecompressorComparisonFuzzer {
    private static final int MAX_COMPARISON_OUTPUT_SIZE = 1024 * 1024;

    protected abstract EmbeddedChannel newLegacyDecoder(int maxAllocation);

    protected abstract Decompressor newDecompressor(int maxAllocation, ByteBufAllocator allocator);

    protected final void fuzz(FuzzedDataProvider fuzzedDataProvider) {
        int maxAllocation = fuzzedDataProvider.consumeInt(1, 1024);
        byte[] input = fuzzedDataProvider.consumeRemainingAsBytes();
        ByteArrayOutputStream legacyOutput = new ByteArrayOutputStream();
        ByteArrayOutputStream decompressorOutput = new ByteArrayOutputStream();
        EmbeddedChannel legacy = newLegacyDecoder(maxAllocation);
        boolean legacyFailed = false;
        boolean decompressorFailed = false;
        boolean decompressorComplete = false;
        boolean outputLimitReached = false;

        try (Decompressor decompressor = newDecompressor(maxAllocation, ByteBufAllocator.DEFAULT)) {
            ByteSplitter.ChunkIterator chunks = DecompressorFuzzingSupport.chunks(input);
            while (chunks.hasNext() && !legacyFailed && !decompressorFailed && !outputLimitReached) {
                chunks.proceed();
                try {
                    legacy.writeInbound(DecompressorFuzzingSupport.inputBuffer(legacy.alloc(), input, chunks));
                    outputLimitReached |= !drainLegacy(legacy, legacyOutput);
                } catch (DecompressionException ignored) {
                    legacyFailed = true;
                }

                if (!outputLimitReached && decompressor.status() == Decompressor.Status.NEED_INPUT) {
                    try {
                        ByteBuf buffer = DecompressorFuzzingSupport.inputBuffer(ByteBufAllocator.DEFAULT, input, chunks);
                        decompressor.addInput(buffer);
                        outputLimitReached |= !DecompressorFuzzingSupport.drain(
                            decompressor, decompressorOutput, MAX_COMPARISON_OUTPUT_SIZE);
                    } catch (DecompressionException ignored) {
                        decompressorFailed = true;
                    }
                }
            }

            if (!legacyFailed && !outputLimitReached) {
                try {
                    legacy.finish();
                    outputLimitReached |= !drainLegacy(legacy, legacyOutput);
                } catch (DecompressionException ignored) {
                    legacyFailed = true;
                }
            }
            if (!decompressorFailed && !outputLimitReached) {
                try {
                    decompressorComplete = DecompressorFuzzingSupport.finish(
                        decompressor, decompressorOutput, MAX_COMPARISON_OUTPUT_SIZE);
                } catch (DecompressionException ignored) {
                    decompressorFailed = true;
                }
            }

            if (!legacyFailed && !decompressorFailed && !outputLimitReached && decompressorComplete
                && !Arrays.equals(legacyOutput.toByteArray(), decompressorOutput.toByteArray())) {
                throw new AssertionError("The legacy decoder and direct decompressor produced different output");
            }
        } finally {
            legacy.finishAndReleaseAll();
        }
        LeakPresenceDetector.check();
        FlagAppender.checkTriggered();
    }

    private static boolean drainLegacy(EmbeddedChannel channel, ByteArrayOutputStream output) {
        while (true) {
            ByteBuf buffer = channel.readInbound();
            if (buffer == null) {
                return true;
            }
            try {
                int readableBytes = buffer.readableBytes();
                if (readableBytes > DecompressorFuzzingSupport.MAX_OUTPUT_BUFFER_SIZE) {
                    throw new AssertionError("Legacy decoder produced an output buffer larger than 1 MiB");
                }
                if (readableBytes > MAX_COMPARISON_OUTPUT_SIZE - output.size()) {
                    return false;
                }
                byte[] bytes = new byte[readableBytes];
                buffer.readBytes(bytes);
                output.writeBytes(bytes);
            } finally {
                buffer.release();
            }
        }
    }
}
