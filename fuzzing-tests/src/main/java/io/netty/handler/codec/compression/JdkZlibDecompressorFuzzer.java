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
import io.micronaut.fuzzing.FlagAppender;
import io.micronaut.fuzzing.FuzzTarget;
import io.micronaut.fuzzing.HttpDict;
import io.micronaut.fuzzing.runner.LocalJazzerRunner;
import io.micronaut.fuzzing.util.ByteSplitter;
import io.netty.buffer.ByteBuf;
import io.netty.buffer.ByteBufAllocator;
import io.netty.util.LeakPresenceDetector;

/**
 * Fuzzes the direct JDK zlib decompressor API with fragmented input.
 */
@FuzzTarget
@HttpDict
public final class JdkZlibDecompressorFuzzer {
    private JdkZlibDecompressorFuzzer() {
    }

    public static void fuzzerTestOneInput(FuzzedDataProvider fuzzedDataProvider) {
        int maxAllocation = fuzzedDataProvider.consumeInt(1, 1024);
        byte[] input = fuzzedDataProvider.consumeRemainingAsBytes();
        try (Decompressor decompressor = JdkZlibDecompressor.builder()
                .maxAllocation(maxAllocation)
                .build(ByteBufAllocator.DEFAULT)) {
            ByteSplitter.ChunkIterator chunks = DecompressorFuzzingSupport.chunks(input);
            while (chunks.hasNext() && decompressor.status() == Decompressor.Status.NEED_INPUT) {
                chunks.proceed();
                ByteBuf buffer = DecompressorFuzzingSupport.inputBuffer(ByteBufAllocator.DEFAULT, input, chunks);
                decompressor.addInput(buffer);
                DecompressorFuzzingSupport.drain(decompressor, null);
            }
            DecompressorFuzzingSupport.finish(decompressor, null);
        } catch (DecompressionException ignored) {
            // Random input is usually not a valid zlib stream.
        }
        LeakPresenceDetector.check();
        FlagAppender.checkTriggered();
    }

    public static void main(String[] args) {
        LocalJazzerRunner.create(JdkZlibDecompressorFuzzer.class).fuzz();
    }
}
