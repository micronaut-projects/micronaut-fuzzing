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
import io.micronaut.fuzzing.FuzzTarget;
import io.micronaut.fuzzing.HttpDict;
import io.micronaut.fuzzing.runner.LocalJazzerRunner;
import io.netty.channel.embedded.EmbeddedChannel;

/**
 * Fuzzing support type.
 */
@FuzzTarget
@HttpDict
@Dict({
    "zstd", "zstandard", "content-encoding: zstd\r\n", "hello", "foobar"
})
public class ZstdEncoderFuzzer extends EmbeddedChannelFuzzerBase {
    private static final int MIN_COMPRESSION_LEVEL = -5;
    private static final int MAX_COMPRESSION_LEVEL = 22;
    private static final int MAX_BLOCK_SIZE = 1 << 20;
    /*
     * maxEncodeSize is deliberately not fuzzed. It is only used by ZstdEncoder.allocateBuffer, which
     * throws when compressBound(min(blockSize, input)) exceeds it. MessageToByteEncoder.write calls
     * allocateBuffer outside the try/finally that releases the input message, so that exception leaks
     * the input buffer (a known Netty bug). Use a limit that can never be exceeded instead.
     */
    private static final int MAX_ENCODE_SIZE = Integer.MAX_VALUE;
    private final int compressionLevel;
    private final int blockSize;

    public ZstdEncoderFuzzer(FuzzedDataProvider fuzzedDataProvider) {
        compressionLevel = fuzzedDataProvider.consumeInt(MIN_COMPRESSION_LEVEL, MAX_COMPRESSION_LEVEL);
        blockSize = fuzzedDataProvider.consumeInt(1, MAX_BLOCK_SIZE);
        inputCpuTime = 500;
    }

    @Override
    protected EmbeddedChannel setUp() {
        // encoders are not @Sharable, so create a fresh one for each attempt
        return new EmbeddedChannel(new ZstdEncoder(compressionLevel, blockSize, MAX_ENCODE_SIZE));
    }

    @Override
    protected boolean isOutbound() {
        return true;
    }

    public static void fuzzerTestOneInput(FuzzedDataProvider fuzzedDataProvider) {
        if (!Zstd.isAvailable()) {
            return;
        }
        var fuzzer = new ZstdEncoderFuzzer(fuzzedDataProvider);
        fuzzer.test(fuzzedDataProvider);
    }

    public static void main(String[] args) {
        LocalJazzerRunner.create(ZstdEncoderFuzzer.class).fuzz();
    }
}
