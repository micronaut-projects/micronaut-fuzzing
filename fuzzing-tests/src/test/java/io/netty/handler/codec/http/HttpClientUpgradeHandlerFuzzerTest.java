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
package io.netty.handler.codec.http;

import com.code_intelligence.jazzer.api.CannedFuzzedDataProvider;
import io.netty.handler.codec.http2.Http2Error;
import io.netty.handler.codec.http2.Http2Exception;
import org.junit.jupiter.api.Test;

import java.nio.charset.StandardCharsets;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

class HttpClientUpgradeHandlerFuzzerTest {
    @Test
    void successfulUpgrade() {
        run("HTTP/1.1 101 Switching Protocols\r\n"
            + "Connection: Upgrade\r\n"
            + "Upgrade: h2c\r\n"
            + "\r\n"
            + "SEP"
            // empty SETTINGS frame
            + "\0\0\0\4\0\0\0\0\0");
    }

    @Test
    void rejectedUpgrade() {
        run("HTTP/1.1 200 OK\r\n"
            + "Content-Length: 5\r\n"
            + "\r\n"
            + "hello");
    }

    @Test
    void unexpectedUpgradeProtocol() {
        run("HTTP/1.1 101 Switching Protocols\r\n"
            + "Connection: Upgrade\r\n"
            + "Upgrade: websocket\r\n"
            + "\r\n");
    }

    @Test
    void oversizedUpgradeResponse() {
        run("HTTP/1.1 101 Switching Protocols\r\n"
            + "Connection: Upgrade\r\n"
            + "Upgrade: h2c\r\n"
            + "Content-Length: 6101\r\n"
            + "\r\n"
            + "abc");
    }

    @Test
    void invalidHttp2Frame() {
        run("HTTP/1.1 101 Switching Protocols\r\n"
            + "Connection: Upgrade\r\n"
            + "Upgrade: h2c\r\n"
            + "\r\n"
            + "SEP"
            // SETTINGS frame with a length that is not a multiple of 6
            + "\0\0\1\4\0\0\0\0\0\0");
    }

    @Test
    void truncatedHeaderBlock() {
        run("HTTP/1.1 101 Switching Protocols\r\n"
            + "Connection: Upgrade\r\n"
            + "Upgrade: h2c\r\n"
            + "\r\n"
            + "SEP"
            // empty SETTINGS frame
            + "\0\0\0\4\0\0\0\0\0"
            // HEADERS frame on the upgrade stream with END_HEADERS
            + "\0\0\5\1\4\0\0\0\1"
            // literal header with name "a" and a value length of 5, but only one byte of the value
            + "\u0040\u0001a\u0005x");
    }

    @Test
    void invalidMaxFrameSize() {
        run("HTTP/1.1 101 Switching Protocols\r\n"
            + "Connection: Upgrade\r\n"
            + "Upgrade: h2c\r\n"
            + "\r\n"
            + "SEP"
            // SETTINGS frame with MAX_FRAME_SIZE = 17235974, above the maximum of 2^24-1
            + "\0\0\6\4\0\0\0\0\0"
            + "\0\5\1\7\0\6");
    }

    @Test
    void wrappedValidationErrorAccepted() {
        assertTrue(HttpClientUpgradeHandlerFuzzer.isExpected(
            wrapped("DefaultHttp2FrameReader", "readSettingsFrame",
                thrownBy(new IllegalArgumentException(), "io.netty.handler.codec.http2.Http2Settings"))));
        assertTrue(HttpClientUpgradeHandlerFuzzer.isExpected(
            wrapped("DefaultHttp2HeadersDecoder", "decodeHeaders",
                wrapped("HpackDecoder$Http2HeadersSink", "appendToHeaderList",
                    thrownBy(new IllegalArgumentException(), "io.netty.handler.codec.http2.DefaultHttp2Headers")))));
    }

    @Test
    void wrappedBugReported() {
        // other exception types
        assertFalse(HttpClientUpgradeHandlerFuzzer.isExpected(
            wrapped("DefaultHttp2FrameReader", "readSettingsFrame",
                thrownBy(new NullPointerException(), "io.netty.handler.codec.http2.Http2Settings"))));
        assertFalse(HttpClientUpgradeHandlerFuzzer.isExpected(
            wrapped("DefaultHttp2HeadersDecoder", "decodeHeaders",
                thrownBy(new IndexOutOfBoundsException(), "io.netty.handler.codec.http2.HpackDecoder"))));
        // IllegalArgumentException from outside the HTTP/2 codec
        assertFalse(HttpClientUpgradeHandlerFuzzer.isExpected(
            wrapped("DefaultHttp2HeadersDecoder", "decodeHeaders",
                thrownBy(new IllegalArgumentException(), "io.netty.buffer.AbstractByteBuf"))));
        assertFalse(HttpClientUpgradeHandlerFuzzer.isExpected(
            wrapped("DefaultHttp2HeadersDecoder", "decodeHeaders",
                thrownBy(new IllegalArgumentException(), "io.netty.handler.codec.http2.foo.Bar"))));
        // IllegalArgumentException with a cause
        IllegalArgumentException withCause = new IllegalArgumentException(new NullPointerException());
        assertFalse(HttpClientUpgradeHandlerFuzzer.isExpected(
            wrapped("DefaultHttp2FrameReader", "readSettingsFrame",
                thrownBy(withCause, "io.netty.handler.codec.http2.Http2Settings"))));
        // Http2Exception created somewhere else
        assertFalse(HttpClientUpgradeHandlerFuzzer.isExpected(
            wrapped("DefaultHttp2ConnectionDecoder$FrameReadListener", "onDataRead",
                thrownBy(new IllegalArgumentException(), "io.netty.handler.codec.http2.Http2Settings"))));
    }

    private static <T extends Throwable> T thrownBy(T t, String className) {
        t.setStackTrace(new StackTraceElement[]{new StackTraceElement(className, "check", null, -1)});
        return t;
    }

    private static Http2Exception wrapped(String simpleClassName, String method, Throwable cause) {
        Http2Exception e = Http2Exception.connectionError(Http2Error.PROTOCOL_ERROR, cause, "error");
        e.setStackTrace(new StackTraceElement[]{
            new StackTraceElement(Http2Exception.class.getName(), "connectionError", null, -1),
            new StackTraceElement("io.netty.handler.codec.http2." + simpleClassName, method, null, -1),
        });
        return e;
    }

    @Test
    void sameInstanceTwice() {
        HttpClientUpgradeHandlerFuzzer fuzzer = new HttpClientUpgradeHandlerFuzzer();
        fuzzer.test(provider("HTTP/1.1 101 Switching Protocols\r\nUpgrade: h2c\r\nContent-Length: 6101\r\n\r\n"));
        fuzzer.test(provider("HTTP/1.1 101 Switching Protocols\r\nUpgrade: h2c\r\n\r\n"));
    }

    private static void run(String input) {
        HttpClientUpgradeHandlerFuzzer.fuzzerTestOneInput(provider(input));
    }

    private static CannedFuzzedDataProvider provider(String input) {
        return CannedFuzzedDataProvider.create(List.<Object>of(input.getBytes(StandardCharsets.ISO_8859_1)));
    }
}
