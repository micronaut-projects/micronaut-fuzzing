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
    private final BrotliOptions options;

    public BrotliEncoderFuzzer(FuzzedDataProvider fuzzedDataProvider) {
        int quality = fuzzedDataProvider.consumeInt(0, 11);
        int window = fuzzedDataProvider.consumeInt(10, 24);
        BrotliMode mode = MODES[fuzzedDataProvider.consumeInt(0, MODES.length - 1)];
        options = StandardCompressionOptions.brotli(quality, window, mode);
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
