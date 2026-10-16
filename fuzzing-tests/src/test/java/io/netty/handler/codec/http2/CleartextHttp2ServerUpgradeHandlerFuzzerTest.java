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
    void ignoresUpgradeAfterCloseNpe() throws Exception {
        // https://github.com/netty/netty/pull/17871
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
    void ignoresInvalidPathInUpgradeRequest() throws Exception {
        // https://github.com/netty/netty/pull/17869
        fuzz("GET /a\u007fb HTTP/1.1\r\n" + UPGRADE_HEADERS + "\r\n");
    }

    @Test
    void ignoresInvalidAuthorityInUpgradeRequest() throws Exception {
        // https://github.com/netty/netty/pull/17869
        fuzz("GET Upgrade-Insecure-Request:// HTTP/1.1\r\n" + UPGRADE_HEADERS + "\r\n");
    }

    @Test
    void reportsSimilarExceptionsFromOtherPlaces() {
        CleartextHttp2ServerUpgradeHandlerFuzzer fuzzer = new CleartextHttp2ServerUpgradeHandlerFuzzer();

        NullPointerException npe = new NullPointerException();
        npe.setStackTrace(new StackTraceElement[]{
            frame(DefaultHttp2Connection.class, "stream"),
            frame(Http2FrameCodec.class, "userEventTriggered")
        });
        assertThrows(NullPointerException.class, () -> fuzzer.onException(npe));

        IllegalArgumentException iae = new IllegalArgumentException();
        iae.setStackTrace(new StackTraceElement[]{
            frame(HttpConversionUtil.class, "toHttp2Headers"),
            frame(HttpToHttp2ConnectionHandler.class, "write")
        });
        assertThrows(IllegalArgumentException.class, () -> fuzzer.onException(iae));
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
