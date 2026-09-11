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
import io.netty.handler.codec.EncoderException;
import io.netty.handler.codec.PrematureChannelClosureException;
import net.jpountz.lz4.LZ4Factory;

import javax.net.ssl.SSLException;
import java.nio.channels.ClosedChannelException;
import java.util.zip.Adler32;
import java.util.zip.CRC32;
import java.util.zip.Checksum;

/**
 * Fuzzing support type.
 */
@FuzzTarget
@HttpDict
@Dict({
    "lz4", "content-encoding: lz4\r\n", "hello", "foobar"
})
public class Lz4FrameEncoderFuzzer extends EmbeddedChannelFuzzerBase {
    private static final int MIN_BLOCK_SIZE = 64;
    private static final int MAX_BLOCK_SIZE = 1 << 20;
    private static final LZ4Factory[] FACTORIES = {
        LZ4Factory.safeInstance(),
        LZ4Factory.fastestJavaInstance()
    };
    private final Lz4FrameEncoder encoder;

    public Lz4FrameEncoderFuzzer(FuzzedDataProvider fuzzedDataProvider) {
        encoder = nextEncoder(fuzzedDataProvider);
        inputCpuTime = 200;
    }

    @Override
    protected EmbeddedChannel setUp() {
        return new EmbeddedChannel(encoder);
    }

    @Override
    protected void onException(Exception e) {
        if (e instanceof CompressionException
            || e instanceof PrematureChannelClosureException
            || e instanceof ClosedChannelException
            || e instanceof EncoderException && e.getCause() instanceof CompressionException) {
            return;
        }
        super.onException(e);
    }

    private static Lz4FrameEncoder nextEncoder(FuzzedDataProvider fuzzedDataProvider) {
        LZ4Factory factory = FACTORIES[fuzzedDataProvider.consumeInt(0, FACTORIES.length - 1)];
        boolean highCompressor = fuzzedDataProvider.consumeBoolean();
        int blockSize = fuzzedDataProvider.consumeInt(MIN_BLOCK_SIZE, MAX_BLOCK_SIZE);
        return new Lz4FrameEncoder(factory, highCompressor, blockSize, nextChecksum(fuzzedDataProvider));
    }

    private static Checksum nextChecksum(FuzzedDataProvider fuzzedDataProvider) {
        return switch (fuzzedDataProvider.consumeInt(0, 2)) {
            case 0 -> new Lz4XXHash32(fuzzedDataProvider.consumeInt());
            case 1 -> new Adler32();
            case 2 -> new CRC32();
            default -> throw new IllegalStateException("Unexpected checksum type");
        };
    }

    @Override
    protected boolean isOutbound() {
        return true;
    }

    public static void fuzzerTestOneInput(FuzzedDataProvider fuzzedDataProvider) throws SSLException {
        var fuzzer = new Lz4FrameEncoderFuzzer(fuzzedDataProvider);
        fuzzer.test(fuzzedDataProvider);
    }

    public static void main(String[] args) {
        LocalJazzerRunner.create(Lz4FrameEncoderFuzzer.class).fuzz();
    }
}
