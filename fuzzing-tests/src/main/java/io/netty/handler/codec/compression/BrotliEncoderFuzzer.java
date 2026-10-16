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
    "brotli", "content-encoding: br\r\n", "hello", "foobar"
})
public class BrotliEncoderFuzzer extends EmbeddedChannelFuzzerBase {
    private static final BrotliMode[] MODES = BrotliMode.values();
    /**
     * At quality 10 and 11, brotli runs zopfli and block splitting for every metablock.
     * {@link BrotliEncoder} flushes every write as its own metablock, so each small input chunk
     * costs about 0.3ms. With 3-byte chunks between separators, this is up to about 65 budget
     * units per input byte. Lower qualities stay below 2 units per input byte.
     */
    private static final long HIGH_QUALITY_INPUT_CPU_TIME = 150;
    private final BrotliOptions options;

    public BrotliEncoderFuzzer(FuzzedDataProvider fuzzedDataProvider) {
        int quality = fuzzedDataProvider.consumeInt(0, 11);
        int window = fuzzedDataProvider.consumeInt(10, 24);
        BrotliMode mode = MODES[fuzzedDataProvider.consumeInt(0, MODES.length - 1)];
        options = StandardCompressionOptions.brotli(quality, window, mode);
        if (quality >= 10) {
            inputCpuTime = HIGH_QUALITY_INPUT_CPU_TIME;
        }
    }

    public static void fuzzerTestOneInput(FuzzedDataProvider fuzzedDataProvider) {
        if (!Brotli.isAvailable()) {
            return;
        }
        new BrotliEncoderFuzzer(fuzzedDataProvider).test(fuzzedDataProvider);
    }

    @Override
    protected EmbeddedChannel setUp() {
        return new EmbeddedChannel(new BrotliEncoder(options));
    }

    @Override
    protected boolean isOutbound() {
        return true;
    }

    public static void main(String[] args) {
        LocalJazzerRunner.create(BrotliEncoderFuzzer.class).fuzz();
    }
}
