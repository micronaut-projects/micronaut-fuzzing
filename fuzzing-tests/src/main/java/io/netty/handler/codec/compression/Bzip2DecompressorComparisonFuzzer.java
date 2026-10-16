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
    protected boolean isExpectedException(RuntimeException exception) {
        return isUnvalidatedHuffmanCodeLength(exception);
    }

    @Override
    protected boolean isExpectedLegacyException(Exception exception) {
        // ByteToMessageDecoder wraps unexpected exceptions in a DecoderException, so look at the cause
        return super.isExpectedLegacyException(exception)
            || (exception instanceof DecoderException && isUnvalidatedHuffmanCodeLength(exception.getCause()));
    }

    /**
     * Netty bug: Huffman code lengths outside 1..23 are not rejected and make
     * {@code Bzip2HuffmanStageDecoder.createHuffmanDecodingTables} index out of bounds. Fixed by
     * <a href="https://github.com/netty/netty/pull/17812">netty/netty#17812</a>; remove this once it is released.
     *
     * @param exception The exception
     * @return {@code true} if this is the known bug
     */
    static boolean isUnvalidatedHuffmanCodeLength(Throwable exception) {
        if (!(exception instanceof ArrayIndexOutOfBoundsException) || exception.getCause() != null) {
            return false;
        }
        StackTraceElement[] trace = exception.getStackTrace();
        return trace.length > 0
            && trace[0].getClassName().equals(Bzip2HuffmanStageDecoder.class.getName())
            && trace[0].getMethodName().equals("createHuffmanDecodingTables");
    }

    public static void fuzzerTestOneInput(FuzzedDataProvider data) {
        new Bzip2DecompressorComparisonFuzzer().fuzz(data);
    }

    public static void main(String[] args) {
        LocalJazzerRunner.create(Bzip2DecompressorComparisonFuzzer.class).fuzz();
    }
}
