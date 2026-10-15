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
import io.micronaut.fuzzing.DictResource;
import io.micronaut.fuzzing.FuzzTarget;
import io.micronaut.fuzzing.runner.LocalJazzerRunner;
import io.netty.buffer.ByteBufAllocator;
import io.netty.channel.embedded.EmbeddedChannel;
import io.netty.handler.codec.DecoderException;

/**
 * Compares the legacy JDK zlib decoder with the direct decompressor API.
 */
@FuzzTarget
@DictResource("dictionaries/zlib.dict")
public final class JdkZlibDecompressorComparisonFuzzer extends AbstractDecompressorComparisonFuzzer {
    private final JdkZlibFuzzConfig config;

    JdkZlibDecompressorComparisonFuzzer(JdkZlibFuzzConfig config) {
        if (config.useDictionary() && config.wrapper() != ZlibWrapper.ZLIB) {
            // the legacy decoder only supports a preset dictionary with the ZLIB wrapper
            config = new JdkZlibFuzzConfig(config.wrapper(), config.decompressConcatenated(), false);
        }
        this.config = config;
    }

    @Override
    protected EmbeddedChannel newLegacyDecoder(int size) {
        return new EmbeddedChannel(config.newLegacyDecoder(size));
    }

    @Override
    protected Decompressor newDecompressor(int size, ByteBufAllocator allocator) {
        return config.newDecompressor(size, allocator);
    }

    @Override
    protected boolean isExpectedException(RuntimeException exception) {
        // Netty bug: an unexpected preset dictionary ID is not reported as DecompressionException.
        // Fixed by https://github.com/netty/netty/pull/17838; remove this once it is released.
        return JdkZlibFuzzConfig.isDictionaryMismatch(exception, JdkZlibDecompressor.class);
    }

    @Override
    protected boolean isExpectedLegacyException(Exception exception) {
        // Netty bug: an unexpected preset dictionary ID is not reported as DecompressionException.
        // Fixed by https://github.com/netty/netty/pull/17838; remove this once it is released.
        return super.isExpectedLegacyException(exception) || (exception instanceof DecoderException
            && JdkZlibFuzzConfig.isDictionaryMismatch(exception.getCause(), JdkZlibDecoder.class));
    }

    public static void fuzzerTestOneInput(FuzzedDataProvider data) {
        new JdkZlibDecompressorComparisonFuzzer(JdkZlibFuzzConfig.consume(data)).fuzz(data);
    }

    public static void main(String[] args) {
        LocalJazzerRunner.create(JdkZlibDecompressorComparisonFuzzer.class).fuzz();
    }
}
