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

import io.netty.channel.embedded.EmbeddedChannel;
import com.code_intelligence.jazzer.api.FuzzedDataProvider;
import io.micronaut.fuzzing.FuzzTarget;
import io.micronaut.fuzzing.HttpDict;
import io.micronaut.fuzzing.runner.LocalJazzerRunner;


/**
 * Fuzzing support type.
 */
@FuzzTarget
@HttpDict
public class BrotliDecoderFuzzer extends DecompressorFuzzerBase {
    private final int decompressedPayloadSizeLimit;

    public BrotliDecoderFuzzer(int decompressedPayloadSizeLimit) {
        this.decompressedPayloadSizeLimit = decompressedPayloadSizeLimit;
    }

    @Override
    protected EmbeddedChannel setUp() {
        EmbeddedChannel channel = new EmbeddedChannel();
        channel.pipeline()
            .addLast(new BrotliDecoder(decompressedPayloadSizeLimit));
        return channel;
    }

    public static void fuzzerTestOneInput(FuzzedDataProvider fuzzedDataProvider) {
        int decompressedPayloadSizeLimit = fuzzedDataProvider.consumeInt(10, 1024);
        new BrotliDecoderFuzzer(decompressedPayloadSizeLimit).test(fuzzedDataProvider);
    }

    public static void main(String[] args) {
        LocalJazzerRunner.create(BrotliDecoderFuzzer.class).fuzz();
    }
}
