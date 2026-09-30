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

import io.micronaut.fuzzing.EmbeddedChannelFuzzerBase;
import io.micronaut.fuzzing.sanitizer.SanitizerTransformer;
import io.micronaut.fuzzing.util.ByteSplitter;
import io.netty.buffer.ByteBuf;
import io.netty.buffer.ByteBufAllocator;

import java.io.ByteArrayOutputStream;

/**
 * Common utilities for fuzzing the direct {@link Decompressor} API.
 */
final class DecompressorFuzzingSupport {
    static final int MAX_OUTPUT_BUFFER_SIZE = 1024 * 1024;

    private static final ByteSplitter SPLITTER = ByteSplitter.create(EmbeddedChannelFuzzerBase.SEPARATOR);

    static {
        SanitizerTransformer.installLocally();
    }

    private DecompressorFuzzingSupport() {
    }

    static ByteSplitter.ChunkIterator chunks(byte[] input) {
        return SPLITTER.splitIterator(input);
    }

    static ByteBuf inputBuffer(ByteBufAllocator allocator, byte[] input, ByteSplitter.ChunkIterator chunks) {
        ByteBuf buffer = allocator.buffer(chunks.length());
        buffer.writeBytes(input, chunks.start(), chunks.length());
        return buffer;
    }

    static void drain(Decompressor decompressor, ByteArrayOutputStream output) {
        drain(decompressor, output, Integer.MAX_VALUE);
    }

    static boolean drain(Decompressor decompressor, ByteArrayOutputStream output, int maxOutputSize) {
        while (decompressor.status() == Decompressor.Status.NEED_OUTPUT) {
            ByteBuf buffer = decompressor.takeOutput();
            try {
                int readableBytes = buffer.readableBytes();
                if (readableBytes > MAX_OUTPUT_BUFFER_SIZE) {
                    throw new AssertionError("Decompressor produced an output buffer larger than 1 MiB");
                }
                if (output != null) {
                    if (readableBytes > maxOutputSize - output.size()) {
                        return false;
                    }
                    byte[] bytes = new byte[readableBytes];
                    buffer.readBytes(bytes);
                    output.writeBytes(bytes);
                }
            } finally {
                buffer.release();
            }
        }
        return true;
    }

    static boolean finish(Decompressor decompressor, ByteArrayOutputStream output) {
        return finish(decompressor, output, Integer.MAX_VALUE);
    }

    static boolean finish(Decompressor decompressor, ByteArrayOutputStream output, int maxOutputSize) {
        if (!drain(decompressor, output, maxOutputSize)) {
            return false;
        }
        if (decompressor.status() == Decompressor.Status.NEED_INPUT) {
            decompressor.endOfInput();
            if (!drain(decompressor, output, maxOutputSize)) {
                return false;
            }
        }
        return decompressor.status() == Decompressor.Status.COMPLETE;
    }
}
