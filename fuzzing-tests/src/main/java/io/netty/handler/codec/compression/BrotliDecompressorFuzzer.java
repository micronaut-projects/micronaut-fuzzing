/* Copyright 2017-2026 original authors */
package io.netty.handler.codec.compression;

import com.code_intelligence.jazzer.api.FuzzedDataProvider;
import io.micronaut.fuzzing.FuzzTarget;
import io.micronaut.fuzzing.runner.LocalJazzerRunner;
import io.netty.buffer.ByteBufAllocator;

/**
 * Fuzzes the direct Brotli decompressor API.
 */
@FuzzTarget
public final class BrotliDecompressorFuzzer extends AbstractDirectDecompressorFuzzer {
    @Override
    protected Decompressor newDecompressor(int size, ByteBufAllocator allocator) {
        return BrotliDecompressor.builder().maxOutputChunkSize(size).build(allocator);
    }

    public static void fuzzerTestOneInput(FuzzedDataProvider data) {
        new BrotliDecompressorFuzzer().fuzz(data);
    }

    public static void main(String[] args) {
        LocalJazzerRunner.create(BrotliDecompressorFuzzer.class).fuzz();
    }
}
