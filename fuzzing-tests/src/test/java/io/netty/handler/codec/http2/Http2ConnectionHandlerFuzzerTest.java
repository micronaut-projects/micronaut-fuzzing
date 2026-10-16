package io.netty.handler.codec.http2;

import com.code_intelligence.jazzer.api.CannedFuzzedDataProvider;
import org.junit.jupiter.api.Test;

import java.nio.charset.StandardCharsets;
import java.util.List;

class Http2ConnectionHandlerFuzzerTest {
    private static final byte[] EMPTY_SETTINGS_FRAME = {
        0, 0, 0,
        4,
        0,
        0, 0, 0, 0
    };

    @Test
    void fuzzesConnectionPrefaceAndSettingsAcrossChunks() throws Exception {
        Http2ConnectionHandlerFuzzer.fuzzerTestOneInput(CannedFuzzedDataProvider.create(List.<Object>of(
            concat(bytes("PRI * HTTP/2.0\r\n\r\nSSEPM\r\n\r\nSEP"), EMPTY_SETTINGS_FRAME)
        )));
    }

    @Test
    void handlesInvalidHttp1PrefaceAsExpectedNettyValidation() throws Exception {
        Http2ConnectionHandlerFuzzer.fuzzerTestOneInput(CannedFuzzedDataProvider.create(List.<Object>of(
            bytes("GET / HTTP/1.1\r\nHost: localhost\r\n\r\n")
        )));
    }

    @Test
    void openStreamWithPartialFrameAtEnd() throws Exception {
        // stream 1 stays open and the decoder holds a partial frame header when the channel is closed
        byte[] hpack = {(byte) 0x82, (byte) 0x86, (byte) 0x84, 0x41, 0x01, 'a'};
        byte[] headers = concat(new byte[]{0, 0, 6, 1, 4, 0, 0, 0, 1}, hpack);
        Http2ConnectionHandlerFuzzer.fuzzerTestOneInput(CannedFuzzedDataProvider.create(List.<Object>of(
            concat(concat(concat(bytes("PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n"), EMPTY_SETTINGS_FRAME), headers), new byte[]{0, 0, 5})
        )));
    }

    private static byte[] bytes(String value) {
        return value.getBytes(StandardCharsets.US_ASCII);
    }

    private static byte[] concat(byte[] first, byte[] second) {
        byte[] result = new byte[first.length + second.length];
        System.arraycopy(first, 0, result, 0, first.length);
        System.arraycopy(second, 0, result, first.length, second.length);
        return result;
    }
}
