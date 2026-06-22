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
import net.jpountz.lz4.LZ4Factory;

import javax.net.ssl.SSLException;

/**
 * Fuzzing support type.
 */
@FuzzTarget
@HttpDict
public class Lz4FrameDecoderFuzzer extends DecompressorFuzzerBase {
    private static final byte[] WARMUP_COMPRESSED_BLOCK = {0x10, 0};

    public Lz4FrameDecoderFuzzer(FuzzedDataProvider fuzzedDataProvider) {
        warmUpLz4();
        channel.pipeline()
            .addLast(new Lz4FrameDecoder(fuzzedDataProvider.consumeBoolean()));
    }

    private static void warmUpLz4() {
        // lz4-java can load its native implementation during the first decode. Do that before the timed loop.
        LZ4Factory.fastestInstance().fastDecompressor()
            .decompress(WARMUP_COMPRESSED_BLOCK, 0, new byte[1], 0, 1);

        Lz4XXHash32 checksum = new Lz4XXHash32(Lz4Constants.DEFAULT_SEED);
        checksum.update(new byte[0], 0, 0);
        checksum.getValue();
    }

    public static void fuzzerTestOneInput(FuzzedDataProvider fuzzedDataProvider) throws SSLException {
        var fuzzer = new Lz4FrameDecoderFuzzer(fuzzedDataProvider);
        fuzzer.test(fuzzedDataProvider);
    }

    public static void main(String[] args) {
        LocalJazzerRunner.create(Lz4FrameDecoderFuzzer.class).fuzz();
    }
}
