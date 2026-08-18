/* Copyright 2017-2026 original authors */
package io.netty.handler.codec.compression;

import com.code_intelligence.jazzer.api.FuzzedDataProvider;
import io.micronaut.fuzzing.FuzzTarget;
import io.micronaut.fuzzing.runner.LocalJazzerRunner;
import io.netty.buffer.ByteBufAllocator;
import io.netty.channel.embedded.EmbeddedChannel;
import io.netty.handler.codec.DecoderException;

/**
 * Compares the legacy bzip2 decoder with the direct decompressor API.
 */
@FuzzTarget
public final class Bzip2DecompressorComparisonFuzzer extends AbstractDecompressorComparisonFuzzer {
    @Override
    protected EmbeddedChannel newLegacyDecoder(int size) {
        return new EmbeddedChannel(new Bzip2Decoder());
    }

    @Override
    protected Decompressor newDecompressor(int size, ByteBufAllocator allocator) {
        return Bzip2Decompressor.builder().outputBufferSize(size).build(allocator);
    }

    @Override
    protected boolean isExpectedLegacyException(Exception exception) {
        return super.isExpectedLegacyException(exception) || exception instanceof DecoderException;
    }

    public static void fuzzerTestOneInput(FuzzedDataProvider data) {
        new Bzip2DecompressorComparisonFuzzer().fuzz(data);
    }

    public static void main(String[] args) {
        LocalJazzerRunner.create(Bzip2DecompressorComparisonFuzzer.class).fuzz();
    }
}
