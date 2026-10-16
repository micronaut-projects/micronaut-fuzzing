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

import com.aayushatharva.brotli4j.decoder.Decoder;
import com.aayushatharva.brotli4j.decoder.DecoderJNI;
import com.aayushatharva.brotli4j.decoder.DirectDecompress;
import com.code_intelligence.jazzer.api.FuzzedDataProvider;
import io.micronaut.fuzzing.EmbeddedChannelFuzzerBase;
import io.micronaut.fuzzing.FuzzTarget;
import io.micronaut.fuzzing.runner.LocalJazzerRunner;
import io.micronaut.fuzzing.util.ByteSplitter;
import io.netty.buffer.ByteBufAllocator;
import io.netty.channel.embedded.EmbeddedChannel;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.util.Arrays;

/**
 * Compares the legacy Brotli decoder with the direct decompressor API.
 */
@FuzzTarget
public final class BrotliDecompressorComparisonFuzzer extends AbstractDecompressorComparisonFuzzer {
    private static final ByteSplitter SPLITTER = ByteSplitter.create(EmbeddedChannelFuzzerBase.SEPARATOR);

    @Override
    protected EmbeddedChannel newLegacyDecoder(int size) {
        return new EmbeddedChannel(new BrotliDecoder(size));
    }

    @Override
    protected Decompressor newDecompressor(int size, ByteBufAllocator allocator) {
        return BrotliDecompressor.builder().maxOutputChunkSize(size).build(allocator);
    }

    /**
     * Both decoders stop early when brotli4j reports {@code NEEDS_MORE_INPUT} after a pull although it could still
     * produce output, e.g. for highly compressible data. The legacy decoder stops earlier than the direct
     * decompressor, so its output is a strict prefix of the direct output. To make sure that the part of the direct
     * output that cannot be compared with the legacy output is still checked, compare it with brotli4j's own
     * decoder, which does not have this bug.
     * <p>
     * Fixed by https://github.com/netty/netty/pull/17870, remove this once it is released.
     */
    @Override
    protected boolean isExpectedDifference(byte[] input, byte[] legacy, byte[] direct) {
        if (legacy.length >= direct.length || !Arrays.equals(legacy, 0, legacy.length, direct, 0, legacy.length)) {
            return false;
        }
        ByteArrayOutputStream joined = new ByteArrayOutputStream(input.length);
        for (byte[] chunk : SPLITTER.split(input)) {
            joined.writeBytes(chunk);
        }
        DirectDecompress reference;
        try {
            reference = Decoder.decompress(joined.toByteArray(), MAX_OUTPUT);
        } catch (IOException e) {
            // output too large to check
            return true;
        }
        if (reference.getResultStatus() != DecoderJNI.Status.DONE) {
            // the error or truncation lies beyond the output of the direct decompressor
            return true;
        }
        byte[] expected = reference.getDecompressedData();
        return direct.length <= expected.length && Arrays.equals(expected, 0, direct.length, direct, 0, direct.length);
    }

    public static void fuzzerTestOneInput(FuzzedDataProvider data) {
        new BrotliDecompressorComparisonFuzzer().fuzz(data);
    }

    public static void main(String[] args) {
        LocalJazzerRunner.create(BrotliDecompressorComparisonFuzzer.class).fuzz();
    }
}
