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

import com.code_intelligence.jazzer.api.CannedFuzzedDataProvider;
import io.netty.buffer.ByteBufAllocator;
import org.junit.jupiter.api.Test;

import java.io.ByteArrayOutputStream;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.util.Arrays;
import java.util.List;
import java.util.zip.CRC32;
import java.util.zip.Deflater;

import static io.micronaut.fuzzing.EmbeddedChannelFuzzerBase.SEPARATOR;
import static java.nio.charset.StandardCharsets.UTF_8;
import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

class JdkZlibDecompressorFuzzerTest {
    private static final byte[] PLAIN = "hello hello hello world, this is some text to compress. hello world!"
        .repeat(20).getBytes(UTF_8);
    private static final byte[] PLAIN2 = "second member".getBytes(UTF_8);

    @Test
    void zlibSplitAcrossChunks() {
        byte[] compressed = deflate(PLAIN, false, null);
        expectSuccess(ZlibWrapper.ZLIB, false, false, split(compressed, 1, 2, 7, compressed.length - 3), PLAIN);
        expectSuccess(ZlibWrapper.ZLIB_OR_NONE, false, false, split(compressed, 1, 5), PLAIN);
    }

    @Test
    void rawDeflateSplitAcrossChunks() {
        byte[] compressed = deflate(PLAIN, true, null);
        expectSuccess(ZlibWrapper.NONE, false, false, split(compressed, 3, 10), PLAIN);
        expectSuccess(ZlibWrapper.ZLIB_OR_NONE, false, false, split(compressed, 1, 10), PLAIN);
    }

    @Test
    void gzipSplitAcrossChunks() {
        byte[] compressed = gzip(PLAIN, false);
        expectSuccess(ZlibWrapper.GZIP, false, false, split(compressed, 4, 11, compressed.length - 5), PLAIN);
        // header with FEXTRA, FNAME, FCOMMENT and FHCRC, split inside each field
        byte[] withFields = gzip(PLAIN, true);
        expectSuccess(ZlibWrapper.GZIP, false, false, split(withFields, 9, 11, 13, 18, 22, 28, 30), PLAIN);
    }

    @Test
    void concatenatedGzipMembers() {
        byte[] first = gzip(PLAIN, true);
        byte[] second = gzip(PLAIN2, false);
        byte[] input = concat(first, SEPARATOR.getBytes(UTF_8), second);
        expectSuccess(ZlibWrapper.GZIP, true, false, input, concat(PLAIN, PLAIN2));
        expectSuccess(ZlibWrapper.GZIP, true, false, concat(first, second), concat(PLAIN, PLAIN2));
        // without decompressConcatenated, the second member is ignored
        expectSuccess(ZlibWrapper.GZIP, false, false, input, PLAIN);
    }

    @Test
    void presetDictionary() {
        byte[] compressed = deflate(PLAIN, false, JdkZlibFuzzConfig.DICTIONARY);
        expectSuccess(ZlibWrapper.ZLIB, false, true, split(compressed, 3), PLAIN);
        // a dictionary is required but not configured
        expectFailure(ZlibWrapper.ZLIB, false, false, compressed);
        // the dictionary ID does not match the configured dictionary
        byte[] wrongId = compressed.clone();
        wrongId[5] ^= 1;
        expectFailure(ZlibWrapper.ZLIB, false, true, wrongId);
    }

    @Test
    void truncatedInput() {
        byte[] zlib = deflate(PLAIN, false, null);
        expectFailure(ZlibWrapper.ZLIB, false, false, Arrays.copyOf(zlib, zlib.length - 6));
        byte[] gzip = gzip(PLAIN, true);
        expectFailure(ZlibWrapper.GZIP, false, false, Arrays.copyOf(gzip, gzip.length - 3));
        expectFailure(ZlibWrapper.GZIP, true, false, Arrays.copyOf(gzip, 15));
        expectFailure(ZlibWrapper.GZIP, true, false, concat(gzip, Arrays.copyOf(gzip, 5)));
    }

    @Test
    void corruptedChecksum() {
        byte[] zlib = deflate(PLAIN, false, null);
        zlib[zlib.length - 1] ^= 1;
        expectFailure(ZlibWrapper.ZLIB, false, false, zlib);
        byte[] gzip = gzip(PLAIN, false);
        gzip[gzip.length - 8] ^= 1;
        expectFailure(ZlibWrapper.GZIP, false, false, gzip);
        byte[] gzipSize = gzip(PLAIN, false);
        gzipSize[gzipSize.length - 1] ^= 1;
        expectFailure(ZlibWrapper.GZIP, true, false, gzipSize);
        byte[] headerCrc = gzip(PLAIN, true);
        headerCrc[headerCrc.length - deflate(PLAIN, true, null).length - 9] ^= 1;
        expectFailure(ZlibWrapper.GZIP, false, false, headerCrc);
    }

    @Test
    void invalidGzipHeader() {
        byte[] gzip = gzip(PLAIN, false);
        gzip[1] = 0;
        // the legacy decoder only checks the first magic byte and decodes this
        expectFailure(ZlibWrapper.GZIP, false, false, gzip);
    }

    private static void expectSuccess(ZlibWrapper wrapper, boolean concatenated, boolean dictionary, byte[] input,
                                      byte[] expected) {
        for (int size : new int[] {0, 1, 7, 65536}) {
            AbstractDirectDecompressorFuzzer.Result result = new JdkZlibDecompressorFuzzer(
                new JdkZlibFuzzConfig(wrapper, concatenated, dictionary)).decompress(size, input, ByteBufAllocator.DEFAULT);
            assertFalse(result.failed());
            assertArrayEquals(expected, result.output().bytes.toByteArray());
            fuzzBoth(wrapper, concatenated, dictionary, Math.max(size, 1), input);
        }
    }

    private static void expectFailure(ZlibWrapper wrapper, boolean concatenated, boolean dictionary, byte[] input) {
        AbstractDirectDecompressorFuzzer.Result result = new JdkZlibDecompressorFuzzer(
            new JdkZlibFuzzConfig(wrapper, concatenated, dictionary)).decompress(1024, input, ByteBufAllocator.DEFAULT);
        assertTrue(result.failed());
        fuzzBoth(wrapper, concatenated, dictionary, 1024, input);
    }

    private static void fuzzBoth(ZlibWrapper wrapper, boolean concatenated, boolean dictionary, int size, byte[] input) {
        JdkZlibDecompressorFuzzer.fuzzerTestOneInput(provider(wrapper, concatenated, dictionary, size, input));
        JdkZlibDecompressorComparisonFuzzer.fuzzerTestOneInput(provider(wrapper, concatenated, dictionary, size, input));
    }

    private static CannedFuzzedDataProvider provider(ZlibWrapper wrapper, boolean concatenated, boolean dictionary,
                                                     int size, byte[] input) {
        return CannedFuzzedDataProvider.create(List.of(wrapper.ordinal(), concatenated, dictionary, size, input));
    }

    private static byte[] deflate(byte[] input, boolean nowrap, byte[] dictionary) {
        Deflater deflater = new Deflater(Deflater.DEFAULT_COMPRESSION, nowrap);
        try {
            if (dictionary != null) {
                deflater.setDictionary(dictionary);
            }
            deflater.setInput(input);
            deflater.finish();
            ByteArrayOutputStream out = new ByteArrayOutputStream();
            byte[] buf = new byte[256];
            while (!deflater.finished()) {
                out.write(buf, 0, deflater.deflate(buf));
            }
            return out.toByteArray();
        } finally {
            deflater.end();
        }
    }

    /**
     * Build a gzip member. java.util.zip.GZIPOutputStream does not write the optional header fields, so build the
     * header manually.
     */
    private static byte[] gzip(byte[] input, boolean headerFields) {
        ByteArrayOutputStream header = new ByteArrayOutputStream();
        header.writeBytes(new byte[] {0x1f, (byte) 0x8b, 8, (byte) (headerFields ? 0x1e : 0), 1, 2, 3, 4, 0, (byte) 0xff});
        if (headerFields) {
            header.writeBytes(new byte[] {4, 0, 'A', 'P', 0, 0}); // FEXTRA
            header.writeBytes("name\0".getBytes(UTF_8)); // FNAME
            header.writeBytes("comment\0".getBytes(UTF_8)); // FCOMMENT
            CRC32 headerCrc = new CRC32();
            headerCrc.update(header.toByteArray());
            header.write((int) headerCrc.getValue());
            header.write((int) (headerCrc.getValue() >> 8));
        }
        CRC32 crc = new CRC32();
        crc.update(input);
        ByteBuffer trailer = ByteBuffer.allocate(8).order(ByteOrder.LITTLE_ENDIAN);
        trailer.putInt((int) crc.getValue());
        trailer.putInt(input.length);
        return concat(header.toByteArray(), deflate(input, true, null), trailer.array());
    }

    private static byte[] split(byte[] input, int... positions) {
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        int start = 0;
        for (int position : positions) {
            out.write(input, start, position - start);
            out.writeBytes(SEPARATOR.getBytes(UTF_8));
            start = position;
        }
        out.write(input, start, input.length - start);
        return out.toByteArray();
    }

    private static byte[] concat(byte[]... parts) {
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        for (byte[] part : parts) {
            out.writeBytes(part);
        }
        return out.toByteArray();
    }
}
