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
import io.micronaut.fuzzing.Dict;
import io.micronaut.fuzzing.EmbeddedChannelFuzzerBase;
import io.micronaut.fuzzing.sanitizer.SanitizerTransformer;
import io.micronaut.fuzzing.util.ByteSplitter;
import io.netty.buffer.ByteBuf;
import io.netty.buffer.ByteBufAllocator;
import io.netty.util.LeakPresenceDetector;
import io.netty.util.concurrent.FastThreadLocalThread;

import java.io.ByteArrayOutputStream;

/**
 * Base class for fuzzing a {@link Decompressor} directly, without going through a channel handler. The input is split
 * into chunks at {@link EmbeddedChannelFuzzerBase#SEPARATOR} and fed to the decompressor one by one. Only
 * {@link DecompressionException} is accepted as a failure mode; any other exception, a resource leak or a violation of
 * the status contract is reported.
 */
@Dict(EmbeddedChannelFuzzerBase.SEPARATOR)
abstract class AbstractDirectDecompressorFuzzer {
    /**
     * Upper bound on the decompressed output that is retained, to avoid OOM on decompression bombs.
     */
    static final int MAX_OUTPUT = 1024 * 1024;
    static final int MAX_SIZE = 64 * 1024;

    private static final ByteSplitter SPLITTER = ByteSplitter.create(EmbeddedChannelFuzzerBase.SEPARATOR);

    static {
        SanitizerTransformer.installLocally();
    }

    /**
     * Create the decompressor under test.
     *
     * @param size      A fuzzed buffer size parameter, between 1 and {@link #MAX_SIZE}
     * @param allocator The allocator to use
     * @return The decompressor
     */
    protected abstract Decompressor newDecompressor(int size, ByteBufAllocator allocator);

    public final void fuzz(FuzzedDataProvider data) {
        int size = data.consumeInt(1, MAX_SIZE);
        byte[] input = data.consumeRemainingAsBytes();
        FastThreadLocalThread.runWithFastThreadLocal(() -> fuzz(size, input));
        LeakPresenceDetector.check();
    }

    void fuzz(int size, byte[] input) {
        decompress(size, input, ByteBufAllocator.DEFAULT);
    }

    /**
     * Decompress the given input using the direct decompressor API.
     *
     * @param size      The fuzzed buffer size parameter
     * @param input     The input, split at {@link EmbeddedChannelFuzzerBase#SEPARATOR}
     * @param allocator The allocator
     * @return The result
     */
    final Result decompress(int size, byte[] input, ByteBufAllocator allocator) {
        OutputCollector output = new OutputCollector();
        ByteSplitter.ChunkIterator itr = SPLITTER.splitIterator(input);
        try (Decompressor decompressor = newDecompressor(size, allocator)) {
            while (itr.hasNext()) {
                if (drain(decompressor, output) == Decompressor.Status.COMPLETE) {
                    return new Result(output, false);
                }
                itr.proceed();
                ByteBuf buf = allocator.buffer(itr.length());
                buf.writeBytes(input, itr.start(), itr.length());
                decompressor.addInput(buf);
            }
            if (drain(decompressor, output) == Decompressor.Status.NEED_INPUT) {
                decompressor.endOfInput();
                drain(decompressor, output);
            }
            return new Result(output, false);
        } catch (DecompressionException e) {
            return new Result(output, true);
        }
    }

    private static Decompressor.Status drain(Decompressor decompressor, OutputCollector output) {
        while (true) {
            Decompressor.Status status = decompressor.status();
            if (status != Decompressor.Status.NEED_OUTPUT) {
                return status;
            }
            ByteBuf buf = decompressor.takeOutput();
            try {
                output.add(buf);
            } finally {
                buf.release();
            }
        }
    }

    /**
     * Collects decompressed output up to {@link #MAX_OUTPUT} bytes.
     */
    static final class OutputCollector {
        final ByteArrayOutputStream bytes = new ByteArrayOutputStream();
        boolean truncated;

        void add(ByteBuf buf) {
            int n = Math.min(buf.readableBytes(), MAX_OUTPUT - bytes.size());
            if (n < buf.readableBytes()) {
                truncated = true;
            }
            byte[] chunk = new byte[n];
            buf.getBytes(buf.readerIndex(), chunk);
            bytes.writeBytes(chunk);
        }
    }

    /**
     * The result of a decompression attempt.
     *
     * @param output The collected output
     * @param failed Whether decompression failed with an expected exception
     */
    record Result(OutputCollector output, boolean failed) {
    }
}
