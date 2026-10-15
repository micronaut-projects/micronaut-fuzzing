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
import io.micronaut.fuzzing.util.ByteSplitter;
import io.netty.buffer.ByteBuf;
import io.netty.buffer.ByteBufAllocator;
import io.netty.channel.embedded.EmbeddedChannel;
import io.netty.util.internal.PlatformDependent;

import java.util.Arrays;

/**
 * Differential fuzzer base that feeds the same input to a legacy {@link io.netty.channel.ChannelHandler} decoder and
 * to the direct {@link Decompressor} API, and checks that the outputs agree. If both succeed, the outputs must be
 * identical. If either fails, the output of one must be a prefix of the other, since both may emit partial data
 * before detecting corruption.
 */
abstract class AbstractDecompressorComparisonFuzzer extends AbstractDirectDecompressorFuzzer {
    private static final ByteSplitter SPLITTER = ByteSplitter.create(EmbeddedChannelFuzzerBase.SEPARATOR);

    /**
     * Create a channel containing the legacy decoder.
     *
     * @param size The fuzzed buffer size parameter, same as passed to {@link #newDecompressor}
     * @return The channel
     */
    protected abstract EmbeddedChannel newLegacyDecoder(int size);

    /**
     * Whether an exception thrown by the legacy decoder is an expected decoding failure.
     *
     * @param exception The exception
     * @return {@code true} if the exception is expected, {@code false} if it should be reported
     */
    protected boolean isExpectedLegacyException(Exception exception) {
        return exception instanceof DecompressionException;
    }

    @Override
    final void fuzz(int size, byte[] input) {
        Result legacy = decompressLegacy(size, input);
        Result direct = decompress(size, input, ByteBufAllocator.DEFAULT);

        byte[] legacyBytes = legacy.output().bytes.toByteArray();
        byte[] directBytes = direct.output().bytes.toByteArray();
        if (legacy.output().truncated || direct.output().truncated || legacy.failed() || direct.failed()) {
            int common = Math.min(legacyBytes.length, directBytes.length);
            if (!Arrays.equals(legacyBytes, 0, common, directBytes, 0, common)) {
                throw new AssertionError("Decompressed output prefix differs. legacyFailed=" + legacy.failed()
                    + " directFailed=" + direct.failed() + " legacyLength=" + legacyBytes.length
                    + " directLength=" + directBytes.length);
            }
        } else if (!Arrays.equals(legacyBytes, directBytes)) {
            throw new AssertionError("Decompressed output differs. legacyLength=" + legacyBytes.length
                + " directLength=" + directBytes.length);
        }
    }

    private Result decompressLegacy(int size, byte[] input) {
        OutputCollector output = new OutputCollector();
        EmbeddedChannel channel = newLegacyDecoder(size);
        ByteSplitter.ChunkIterator itr = SPLITTER.splitIterator(input);
        try {
            while (itr.hasNext()) {
                itr.proceed();
                ByteBuf buf = channel.alloc().buffer(itr.length());
                buf.writeBytes(input, itr.start(), itr.length());
                channel.writeInbound(buf);
                drainLegacy(channel, output);
            }
            channel.finish();
            drainLegacy(channel, output);
            return new Result(output, false);
        } catch (Exception e) {
            checkLegacyException(e);
            return new Result(output, true);
        } finally {
            try {
                // the decoder may throw again when it sees the channel close
                channel.finishAndReleaseAll();
            } catch (Exception e) {
                checkLegacyException(e);
            }
        }
    }

    private void checkLegacyException(Exception e) {
        if (!isExpectedLegacyException(e)) {
            PlatformDependent.throwException(e);
        }
    }

    private static void drainLegacy(EmbeddedChannel channel, OutputCollector output) {
        ByteBuf buf;
        while ((buf = channel.readInbound()) != null) {
            try {
                output.add(buf);
            } finally {
                buf.release();
            }
        }
    }
}
