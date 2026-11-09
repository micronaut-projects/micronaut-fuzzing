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
import io.micronaut.fuzzing.runner.LocalJazzerRunner;
import io.micronaut.fuzzing.sanitizer.ByteBufArraySanitizer;
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
        // ByteToMessageDecoder wraps unexpected exceptions in a DecoderException, so look at the cause
        return super.isExpectedLegacyException(exception)
            || (exception instanceof DecoderException && isKnownLegacyBug(exception.getCause()));
    }

    /**
     * Whether the cause of a {@link DecoderException} from {@link Bzip2Decoder} is a known bug.
     *
     * @param cause The cause
     * @return {@code true} if this is a known bug
     */
    static boolean isKnownLegacyBug(Throwable cause) {
        return isNextSymbolAfterError(cause) || isInverseBwtAfterError(cause);
    }

    /**
     * Netty bug: {@link Bzip2Decoder} does not stop after an error, and continues from its inconsistent state on the
     * next input or when the channel is closed. After "error decoding block", {@code Bzip2HuffmanStageDecoder.nextSymbol}
     * reads past the end of the selectors. Fixed by
     * <a href="https://github.com/netty/netty/pull/18259">netty/netty#18259</a>; remove this once it is released.
     *
     * @param exception The exception
     * @return {@code true} if this is the known bug
     */
    static boolean isNextSymbolAfterError(Throwable exception) {
        if (!(exception instanceof ArrayIndexOutOfBoundsException) || exception.getCause() != null) {
            return false;
        }
        StackTraceElement[] trace = exception.getStackTrace();
        int i = 0;
        // the sanitizer replaces the load from the selectors array
        if (i < trace.length && trace[i].getClassName().equals(ByteBufArraySanitizer.class.getName())
            && trace[i].getMethodName().equals("baload")) {
            i++;
        }
        return i < trace.length
            && trace[i].getClassName().equals(Bzip2HuffmanStageDecoder.class.getName())
            && trace[i].getMethodName().equals("nextSymbol");
    }

    /**
     * Netty bug: {@link Bzip2Decoder} does not stop after an error (see {@link #isNextSymbolAfterError}). When
     * {@code Bzip2BlockDecompressor.decodeHuffmanData} fails, it has already counted the decoded bytes in
     * {@code bwtByteCounts}, but not stored the block length. When it continues to the end of the block on the next
     * input or when the channel is closed, the byte counts are larger than the block, and
     * {@code initialiseInverseBWT} writes past the end of {@code bwtMergedPointers}. Fixed by
     * <a href="https://github.com/netty/netty/pull/18259">netty/netty#18259</a>; remove this once it is released.
     *
     * @param exception The exception
     * @return {@code true} if this is the known bug
     */
    static boolean isInverseBwtAfterError(Throwable exception) {
        if (!(exception instanceof ArrayIndexOutOfBoundsException) || exception.getCause() != null) {
            return false;
        }
        // the access is to an int array, which the sanitizer does not replace
        StackTraceElement[] trace = exception.getStackTrace();
        return trace.length > 0
            && trace[0].getClassName().equals(Bzip2BlockDecompressor.class.getName())
            && trace[0].getMethodName().equals("initialiseInverseBWT");
    }

    public static void fuzzerTestOneInput(FuzzedDataProvider data) {
        new Bzip2DecompressorComparisonFuzzer().fuzz(data);
    }

    public static void main(String[] args) {
        LocalJazzerRunner.create(Bzip2DecompressorComparisonFuzzer.class).fuzz();
    }
}
