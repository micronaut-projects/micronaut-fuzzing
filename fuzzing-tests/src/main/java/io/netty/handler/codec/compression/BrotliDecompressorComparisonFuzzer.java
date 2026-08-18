/* Copyright 2017-2026 original authors */
package io.netty.handler.codec.compression;

import com.code_intelligence.jazzer.api.FuzzedDataProvider;
import io.micronaut.fuzzing.FuzzTarget;
import io.micronaut.fuzzing.runner.LocalJazzerRunner;
import io.netty.buffer.ByteBufAllocator;
import io.netty.channel.embedded.EmbeddedChannel;

/**
 * Compares the legacy Brotli decoder with the direct decompressor API.
 */
@FuzzTarget
public final class BrotliDecompressorComparisonFuzzer extends AbstractDecompressorComparisonFuzzer {
    @Override
    protected EmbeddedChannel newLegacyDecoder(int size) {
        return new EmbeddedChannel(new BrotliDecoder(size));
    }

    @Override
    protected Decompressor newDecompressor(int size, ByteBufAllocator allocator) {
        return BrotliDecompressor.builder().maxOutputChunkSize(size).build(allocator);
    }

    public static void fuzzerTestOneInput(FuzzedDataProvider data) {
        new BrotliDecompressorComparisonFuzzer().fuzz(data);
    }

    public static void main(String[] args) {
        LocalJazzerRunner.create(BrotliDecompressorComparisonFuzzer.class).fuzz();
    }
}
