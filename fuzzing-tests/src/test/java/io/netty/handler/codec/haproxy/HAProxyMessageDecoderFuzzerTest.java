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
package io.netty.handler.codec.haproxy;

import com.code_intelligence.jazzer.api.CannedFuzzedDataProvider;
import io.netty.handler.codec.DecoderException;
import org.junit.jupiter.api.Test;

import java.io.ByteArrayOutputStream;
import java.util.Arrays;
import java.util.List;

import static java.nio.charset.StandardCharsets.US_ASCII;
import static org.junit.jupiter.api.Assertions.assertThrows;

class HAProxyMessageDecoderFuzzerTest {
    private static final byte[] V2_SIGNATURE = {0x0D, 0x0A, 0x0D, 0x0A, 0x00, 0x0D, 0x0A, 0x51, 0x55, 0x49, 0x54, 0x0A};

    @Test
    void decodesV1Tcp4() {
        run(0, 0, false, ascii("PROXY TCP4 192.168.0.1 192.168.0.11 56324 443\r\nGET / HTTP/1.1\r\n\r\n"));
    }

    @Test
    void decodesV1Tcp6() {
        run(1, 0, false, ascii("PROXY TCP6 2001:db8::1 ::1 56324 443\r\n"));
    }

    @Test
    void decodesV1Unknown() {
        run(2, 100, true, ascii("PROXY UNKNOWN\r\n"));
    }

    @Test
    void decodesSplitInput() {
        run(3, 1024, true, ascii("PROXY TCP4 10.0.0.1 SEP10.0.0.2 1 2\rSEP\npayload"));
    }

    @Test
    void decodesV2Tcp4WithTlvs() {
        ByteArrayOutputStream tlvs = new ByteArrayOutputStream();
        tlv(tlvs, 0x01, ascii("h2"));
        tlv(tlvs, 0x02, ascii("example.com"));
        ByteArrayOutputStream ssl = new ByteArrayOutputStream();
        ssl.write(0x07);
        ssl.writeBytes(new byte[] {0, 0, 0, 0});
        tlv(ssl, 0x21, ascii("TLSv1.3"));
        tlv(ssl, 0x22, ascii("cn"));
        ssl.write(0); // trailing byte after the sub-TLVs, dropped when re-encoding
        tlv(tlvs, 0x20, ssl.toByteArray());
        tlv(tlvs, 0xE0, new byte[0]);
        byte[] addresses = {127, 0, 0, 1, 10, 0, 0, 1, 0x01, (byte) 0xBB, 0, 80};
        run(3, 1024, false, v2(0x21, 0x11, concat(addresses, tlvs.toByteArray())));
    }

    @Test
    void decodesV2Tcp6() {
        byte[] addresses = new byte[36];
        addresses[15] = 1;
        addresses[31] = 1;
        run(0, 0, false, v2(0x21, 0x21, addresses));
    }

    @Test
    void decodesV2UnixWithNonAsciiAddress() {
        byte[] addresses = new byte[216];
        addresses[0] = '/';
        addresses[1] = (byte) 0xFF;
        addresses[108] = '/';
        run(0, 0, false, v2(0x21, 0x31, addresses));
    }

    @Test
    void decodesV2Local() {
        run(0, 0, false, v2(0x20, 0x00, new byte[0]));
    }

    @Test
    void ignoresMalformedHeaders() {
        run(0, 0, false, ascii("PROXY TCP4 192.168.0.1 192.168.0.11 0 443\r\n"));
        run(0, 0, false, ascii("PROXY UDP4 192.168.0.1 192.168.0.11 1 443\r\n"));
        run(0, 0, false, ascii("PROXY TCP4 1.2.3\r\n"));
        run(0, 0, false, ascii("PROXY TCP4 192.168.0.1 192.168.0.11 56324 443 extra padding to exceed the maximum v1 header length of 108 bytes\r\n"));
        run(0, 0, false, v2(0x2F, 0x11, new byte[12]));
        run(0, 0, false, v2(0x21, 0x11, new byte[4]));
    }

    @Test
    void ignoresOversizedV2HeaderFailSlow() {
        byte[] header = v2(0x21, 0x11, new byte[1000]);
        byte[] input = concat(concat(Arrays.copyOf(header, 500), ascii("SEP")),
            Arrays.copyOfRange(header, 500, header.length));
        run(3, 0, false, input);
        run(3, 0, true, input);
    }

    @Test
    void ignoresKnownRelativeHeaderEndBug() {
        // a v2 header over the limit, followed by 16 bytes that look like a header with an empty address block
        run(2, 0, false, concat(v2(0x21, 0x11, new byte[256]), new byte[16]));
    }

    @Test
    void ignoresKnownTlvLengthBug() {
        byte[] addresses = {127, 0, 0, 1, 127, 0, 0, 1, 0x04, (byte) 0xD2, 0, 80};
        run(0, 0, false, v2(0x21, 0x11, concat(addresses, new byte[] {0x01, 0x00, (byte) 0xFF, 'h'})));
    }

    @Test
    void retriesWithFreshDecoder() {
        CannedFuzzedDataProvider provider = CannedFuzzedDataProvider.create(List.of(
            0, true, 0, false,
            ascii("PROXY TCP4 192.168.0.1 192.168.0.11 56324 443\r\n"),
            ascii("PROXY TCP4 192.168.0.1 192.168.0.11 56324 443\r\n")
        ));
        HAProxyMessageDecoderFuzzer fuzzer = new HAProxyMessageDecoderFuzzer(provider);
        // the base class retries an input after a CpuLimitException, calling setUp again
        fuzzer.test(provider);
        fuzzer.test(provider);
    }

    @Test
    void reportsUnexpectedExceptions() {
        HAProxyMessageDecoderFuzzer fuzzer = new HAProxyMessageDecoderFuzzer(
            CannedFuzzedDataProvider.create(List.of(0, true, 0, false)));
        assertThrows(DecoderException.class, () -> fuzzer.onException(new DecoderException(new IndexOutOfBoundsException())));
        assertThrows(DecoderException.class, () -> fuzzer.onException(new DecoderException(new IllegalArgumentException())));
        assertThrows(HAProxyProtocolException.class, () -> fuzzer.onException(
            new HAProxyProtocolException("invalid HAProxy message", new NullPointerException())));
        assertThrows(HAProxyProtocolException.class, () -> fuzzer.onException(
            new HAProxyProtocolException(new IllegalArgumentException())));
        fuzzer.onException(new HAProxyProtocolException("header length (300) exceeds the allowed maximum (232)"));
    }

    private static void run(int constructor, int maxTlvSize, boolean failFast, byte[] input) {
        HAProxyMessageDecoderFuzzer.fuzzerTestOneInput(CannedFuzzedDataProvider.create(List.of(
            constructor, true, maxTlvSize, failFast, input
        )));
    }

    private static byte[] v2(int versionCommand, int family, byte[] addressBlock) {
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        out.writeBytes(V2_SIGNATURE);
        out.write(versionCommand);
        out.write(family);
        out.write(addressBlock.length >> 8);
        out.write(addressBlock.length);
        out.writeBytes(addressBlock);
        return out.toByteArray();
    }

    private static void tlv(ByteArrayOutputStream out, int type, byte[] value) {
        out.write(type);
        out.write(value.length >> 8);
        out.write(value.length);
        out.writeBytes(value);
    }

    private static byte[] concat(byte[] a, byte[] b) {
        byte[] result = Arrays.copyOf(a, a.length + b.length);
        System.arraycopy(b, 0, result, a.length, b.length);
        return result;
    }

    private static byte[] ascii(String s) {
        return s.getBytes(US_ASCII);
    }
}
