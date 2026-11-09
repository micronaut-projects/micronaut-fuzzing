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
package io.netty.handler.codec.http2;

import com.code_intelligence.jazzer.api.CannedFuzzedDataProvider;
import org.junit.jupiter.api.Test;

import java.nio.charset.StandardCharsets;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertThrows;

class CleartextHttp2ServerUpgradeHandlerFuzzerTest {
    private static final String UPGRADE_HEADERS = "Host: x\r\n"
        + "Upgrade: h2c\r\n"
        + "HTTP2-Settings: AAMAAABk\r\n"
        + "Connection: Upgrade, HTTP2-Settings\r\n";

    @Test
    void fuzzesPriorKnowledgePrefaceAcrossChunks() throws Exception {
        CleartextHttp2ServerUpgradeHandlerFuzzer.fuzzerTestOneInput(CannedFuzzedDataProvider.create(List.<Object>of(
            bytes("PRI * HTTP/2.0\r\n\r\nSSEPM\r\n\r\n")
        )));
    }

    @Test
    void fuzzesHttp1UpgradeRequestAcrossChunks() throws Exception {
        CleartextHttp2ServerUpgradeHandlerFuzzer.fuzzerTestOneInput(CannedFuzzedDataProvider.create(List.<Object>of(
            bytes("GET / HTTP/1.1\r\n"
                + "Host: localhost\r\n"
                + "Connection: Upgrade, HTTP2-Settings\r\n"
                + "Upgrade: h2c\r\n"
                + "HTTP2-Settings: AAMAAABkAAQAAP__\r\n"
                + "SEP\r\n")
        )));
    }

    @Test
    void upgradeAfterClose() throws Exception {
        // before netty/netty#17871, Http2FrameCodec threw a NullPointerException
        fuzz("POST / HTTP/1.1\r\n"
            + "Host: x\r\n"
            + "Upgrade: h2c\r\n"
            + "Connection: close\r\n"
            + "Content-Length: 2000\r\n"
            + "\r\n"
            + "x".repeat(2000)
            + "GET / HTTP/1.1\r\n"
            + UPGRADE_HEADERS
            + "\r\n");
    }

    @Test
    void invalidPathInUpgradeRequest() throws Exception {
        // before netty/netty#17869, HttpConversionUtil.toHttp2Headers threw an IllegalArgumentException
        fuzz("GET /a\u007fb HTTP/1.1\r\n" + UPGRADE_HEADERS + "\r\n");
    }

    @Test
    void invalidAuthorityInUpgradeRequest() throws Exception {
        // before netty/netty#17869, HttpConversionUtil.toHttp2Headers threw an IllegalArgumentException
        fuzz("GET Upgrade-Insecure-Request:// HTTP/1.1\r\n" + UPGRADE_HEADERS + "\r\n");
    }

    @Test
    void invalidTeHeaderInUpgradeRequest() throws Exception {
        // before netty/netty#17869, HttpConversionUtil.toHttp2Headers threw an IllegalArgumentException
        fuzz("GET / HTTP/1.1\r\nte: a,\"b\r\n" + UPGRADE_HEADERS + "\r\n");
    }

    @Test
    void ignoresInvalidCookieHeaderInUpgradeRequest() throws Exception {
        // https://github.com/netty/netty/pull/18258
        fuzz("GET / HTTP/1.1\r\ncookie: a=b;  c=d\r\n" + UPGRADE_HEADERS + "\r\n");
    }

    @Test
    void ignoresInvalidTeTrailerInUpgradeRequest() throws Exception {
        // https://github.com/netty/netty/pull/18258
        fuzz("POST / HTTP/1.1\r\nTransfer-Encoding: chunked\r\n" + UPGRADE_HEADERS + "\r\n"
            + "3\r\nabc\r\n0\r\nte: a,\"b\r\n\r\n");
    }

    @Test
    void ignoresInvalidCookieTrailerInUpgradeRequest() throws Exception {
        // https://github.com/netty/netty/pull/18258
        fuzz("POST / HTTP/1.1\r\nTransfer-Encoding: chunked\r\n" + UPGRADE_HEADERS + "\r\n"
            + "3\r\nabc\r\n0\r\ncookie: a=b;  c=d\r\n\r\n");
    }

    @Test
    void reportsSimilarExceptionsFromOtherPlaces() {
        CleartextHttp2ServerUpgradeHandlerFuzzer fuzzer = new CleartextHttp2ServerUpgradeHandlerFuzzer();

        IllegalArgumentException iae = new IllegalArgumentException();
        iae.setStackTrace(new StackTraceElement[]{
            frame(HttpConversionUtil.class, "toHttp2Headers"),
            frame(HttpToHttp2ConnectionHandler.class, "write")
        });
        assertThrows(IllegalArgumentException.class, () -> fuzzer.onException(iae));

        IllegalStateException cookieIse = new IllegalStateException(new IllegalArgumentException());
        cookieIse.setStackTrace(new StackTraceElement[]{
            frame(HttpConversionUtil.class, "splitValidCookieHeader"),
            frame(HttpConversionUtil.class, "toHttp2Headers"),
            frame(HttpToHttp2ConnectionHandler.class, "write")
        });
        assertThrows(IllegalStateException.class, () -> fuzzer.onException(cookieIse));

        IllegalStateException otherIse = new IllegalStateException();
        otherIse.setStackTrace(new StackTraceElement[]{
            frame(HttpConversionUtil.class, "splitValidCookieHeader"),
            frame(HttpConversionUtil.class, "toHttp2Headers"),
            frame(InboundHttpToHttp2Adapter.class, "handle")
        });
        assertThrows(IllegalStateException.class, () -> fuzzer.onException(otherIse));
    }

    private static StackTraceElement frame(Class<?> cls, String method) {
        return new StackTraceElement(cls.getName(), method, null, -1);
    }

    private static void fuzz(String input) throws Exception {
        CleartextHttp2ServerUpgradeHandlerFuzzer.fuzzerTestOneInput(CannedFuzzedDataProvider.create(List.<Object>of(
            input.getBytes(StandardCharsets.ISO_8859_1)
        )));
    }

    private static byte[] bytes(String value) {
        return value.getBytes(StandardCharsets.US_ASCII);
    }
}
