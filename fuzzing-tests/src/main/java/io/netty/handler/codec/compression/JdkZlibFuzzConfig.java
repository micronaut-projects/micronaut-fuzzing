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
import io.micronaut.fuzzing.sanitizer.ByteBufArraySanitizer;
import io.netty.buffer.ByteBufAllocator;

import java.nio.charset.StandardCharsets;
import java.util.zip.Inflater;

/**
 * Fuzzed configuration shared by the {@link JdkZlibDecompressor} fuzz targets.
 *
 * @param wrapper                The wrapper format
 * @param decompressConcatenated Whether to decompress concatenated gzip members
 * @param useDictionary          Whether to configure {@link #DICTIONARY} as the preset dictionary
 */
record JdkZlibFuzzConfig(ZlibWrapper wrapper, boolean decompressConcatenated, boolean useDictionary) {
    /**
     * Fixed preset dictionary. The fuzzing dictionary contains a zlib header with its adler32 checksum
     * ({@code 7e9110aa}), so that the fuzzer can reach the code that sets the dictionary.
     */
    static final byte[] DICTIONARY = "Hello, preset dictionary for the zlib fuzzer!".getBytes(StandardCharsets.US_ASCII);

    static JdkZlibFuzzConfig consume(FuzzedDataProvider data) {
        return new JdkZlibFuzzConfig(data.pickValue(ZlibWrapper.values()), data.consumeBoolean(), data.consumeBoolean());
    }

    Decompressor newDecompressor(int maxAllocation, ByteBufAllocator allocator) {
        return JdkZlibDecompressor.builder()
            .maxAllocation(maxAllocation)
            .wrapper(wrapper)
            .decompressConcatenated(decompressConcatenated)
            .dictionary(useDictionary ? DICTIONARY : null)
            .build(allocator);
    }

    /**
     * Create the legacy decoder with the same configuration. The legacy decoder only supports a preset dictionary
     * with the {@link ZlibWrapper#ZLIB} wrapper.
     *
     * @param maxAllocation The maximum allocation
     * @return The legacy decoder
     */
    JdkZlibDecoder newLegacyDecoder(int maxAllocation) {
        if (useDictionary) {
            if (wrapper != ZlibWrapper.ZLIB) {
                throw new IllegalStateException("Legacy decoder only supports a dictionary with the ZLIB wrapper");
            }
            return new JdkZlibDecoder(DICTIONARY, maxAllocation);
        }
        return new JdkZlibDecoder(wrapper, decompressConcatenated, maxAllocation);
    }

    /**
     * Whether the given exception is thrown by {@link Inflater#setDictionary} when the dictionary ID in the zlib header
     * does not match the configured dictionary. Both decoders pass that exception through instead of wrapping it in a
     * {@link DecompressionException}.
     *
     * @param exception The exception
     * @param caller    The decoder class that called {@link Inflater#setDictionary}
     * @return {@code true} if this is the dictionary mismatch exception
     */
    static boolean isDictionaryMismatch(Throwable exception, Class<?> caller) {
        if (!(exception instanceof IllegalArgumentException) || exception.getCause() != null) {
            return false;
        }
        StackTraceElement[] trace = exception.getStackTrace();
        int i = 0;
        while (i < trace.length && trace[i].getClassName().equals(Inflater.class.getName())
            && trace[i].getMethodName().equals("setDictionary")) {
            i++;
        }
        if (i == 0) {
            return false;
        }
        if (i < trace.length && trace[i].getClassName().equals(ByteBufArraySanitizer.class.getName())
            && trace[i].getMethodName().equals("inflaterSetDictionary")) {
            i++;
        }
        return i < trace.length && trace[i].getClassName().equals(caller.getName());
    }
}
