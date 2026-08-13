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
import io.netty.buffer.ByteBufAllocator;
import io.netty.channel.embedded.EmbeddedChannel;

/**
 * Compares the output of the legacy JDK zlib decoder with the direct decompressor API.
 */
@FuzzTarget
@HttpDict
public final class JdkZlibDecompressorComparisonFuzzer extends AbstractDecompressorComparisonFuzzer {
    private JdkZlibDecompressorComparisonFuzzer() {
    }

    @Override
    protected EmbeddedChannel newLegacyDecoder(int maxAllocation) {
        return new EmbeddedChannel(new JdkZlibDecoder(maxAllocation));
    }

    @Override
    protected Decompressor newDecompressor(int maxAllocation, ByteBufAllocator allocator) {
        return JdkZlibDecompressor.builder()
            .maxAllocation(maxAllocation)
            .build(allocator);
    }

    public static void fuzzerTestOneInput(FuzzedDataProvider fuzzedDataProvider) {
        new JdkZlibDecompressorComparisonFuzzer().fuzz(fuzzedDataProvider);
    }

    public static void main(String[] args) {
        LocalJazzerRunner.create(JdkZlibDecompressorComparisonFuzzer.class).fuzz();
    }
}
