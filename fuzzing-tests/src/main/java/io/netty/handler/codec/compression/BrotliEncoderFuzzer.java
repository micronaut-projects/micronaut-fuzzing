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
import io.micronaut.fuzzing.FuzzTarget;
import io.micronaut.fuzzing.HttpDict;
import io.micronaut.fuzzing.runner.LocalJazzerRunner;
import io.micronaut.fuzzing.util.ByteSplitter;
import io.netty.buffer.ByteBuf;
import io.netty.channel.embedded.EmbeddedChannel;
import io.netty.util.LeakPresenceDetector;
import io.netty.util.concurrent.FastThreadLocalThread;

/**
 * Fuzzing support type.
 */
@FuzzTarget
@HttpDict
@Dict({
    "SEP", "brotli", "content-encoding: br\r\n", "hello", "foobar"
})
public class BrotliEncoderFuzzer {
    private static final String SEPARATOR = "SEP";
    private static final ByteSplitter SPLITTER = ByteSplitter.create(SEPARATOR);
    private static final int OPTION_BYTES = 3;
    private static final int MAX_CHUNK_COUNT = 16;
    private static final int MAX_CHUNK_BYTES = 4096;
    private static final BrotliMode[] MODES = BrotliMode.values();

    public static void fuzzerTestOneInput(FuzzedDataProvider fuzzedDataProvider) {
        FastThreadLocalThread.runWithFastThreadLocal(() -> test0(fuzzedDataProvider));
    }

    private static void test0(FuzzedDataProvider fuzzedDataProvider) {
        if (!Brotli.isAvailable()) {
            return;
        }

        byte[] allBytes = fuzzedDataProvider.consumeRemainingAsBytes();
        ByteSplitter.ChunkIterator itr = SPLITTER.splitIterator(allBytes);
        itr.proceed();

        EmbeddedChannel channel = new EmbeddedChannel(new BrotliEncoder(nextOptions(allBytes, itr.start(), itr.length())));
        try {
            if (itr.hasNext()) {
                for (int i = 0; i < MAX_CHUNK_COUNT && itr.hasNext(); i++) {
                    itr.proceed();
                    writeOutbound(channel, allBytes, itr.start(), itr.length());
                }
            } else {
                int payloadOffset = itr.start() + Math.min(OPTION_BYTES, itr.length());
                writeOutbound(channel, allBytes, payloadOffset, itr.start() + itr.length() - payloadOffset);
            }
        } finally {
            channel.finishAndReleaseAll();
        }
        LeakPresenceDetector.check();
    }

    private static BrotliOptions nextOptions(byte[] allBytes, int offset, int length) {
        int quality = unsignedByteAt(allBytes, offset, length, 0) % 12;
        int window = 10 + unsignedByteAt(allBytes, offset, length, 1) % 15;
        BrotliMode mode = MODES[unsignedByteAt(allBytes, offset, length, 2) % MODES.length];
        return StandardCompressionOptions.brotli(quality, window, mode);
    }

    private static int unsignedByteAt(byte[] bytes, int offset, int length, int index) {
        if (index >= length) {
            return 0;
        }
        return bytes[offset + index] & 0xff;
    }

    private static void writeOutbound(EmbeddedChannel channel, byte[] bytes, int offset, int length) {
        int chunkLength = Math.min(MAX_CHUNK_BYTES, length);
        ByteBuf input = channel.alloc().buffer(chunkLength);
        input.writeBytes(bytes, offset, chunkLength);
        channel.writeOutbound(input);
    }

    public static void main(String[] args) {
        LocalJazzerRunner.create(BrotliEncoderFuzzer.class).fuzz();
    }
}
