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
import io.micronaut.fuzzing.FuzzTarget;
import io.micronaut.fuzzing.HttpDict;
import io.micronaut.fuzzing.runner.LocalJazzerRunner;
import io.netty.handler.codec.DecoderException;

import javax.net.ssl.SSLException;

/**
 * Fuzzing support type.
 */
@FuzzTarget
@HttpDict
public class FastLzFrameDecoderFuzzer extends DecompressorFuzzerBase {
    public FastLzFrameDecoderFuzzer(FuzzedDataProvider fuzzedDataProvider) {
        channel.pipeline()
            .addLast(new FastLzFrameDecoder(fuzzedDataProvider.consumeBoolean()));
    }

    @Override
    protected void onException(Exception e) {
        if (e instanceof DecoderException) {
            return;
        }
        super.onException(e);
    }

    public static void fuzzerTestOneInput(FuzzedDataProvider fuzzedDataProvider) throws SSLException {
        var fuzzer = new FastLzFrameDecoderFuzzer(fuzzedDataProvider);
        fuzzer.test(fuzzedDataProvider);
    }

    public static void main(String[] args) {
        LocalJazzerRunner.create(FastLzFrameDecoderFuzzer.class).fuzz();
    }
}
