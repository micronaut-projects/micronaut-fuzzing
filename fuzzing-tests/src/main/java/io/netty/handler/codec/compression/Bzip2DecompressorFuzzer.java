/* Copyright 2017-2026 original authors */
package io.netty.handler.codec.compression;

import com.code_intelligence.jazzer.api.FuzzedDataProvider;
import io.micronaut.fuzzing.FuzzTarget;
import io.micronaut.fuzzing.runner.LocalJazzerRunner;
import io.netty.buffer.ByteBufAllocator;

/**
 * Fuzzes the direct bzip2 decompressor API.
 */
@FuzzTarget
public final class Bzip2DecompressorFuzzer extends AbstractDirectDecompressorFuzzer {
    @Override
    protected Decompressor newDecompressor(int size, ByteBufAllocator allocator) {
        return Bzip2Decompressor.builder().outputBufferSize(size).build(allocator);
    }

    public static void fuzzerTestOneInput(FuzzedDataProvider data) {
        new Bzip2DecompressorFuzzer().fuzz(data);
    }

    public static void main(String[] args) {
        LocalJazzerRunner.create(Bzip2DecompressorFuzzer.class).fuzz();
    }
}
