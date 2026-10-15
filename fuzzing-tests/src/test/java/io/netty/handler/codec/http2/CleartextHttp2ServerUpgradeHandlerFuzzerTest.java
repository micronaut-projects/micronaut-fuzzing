package io.netty.handler.codec.http2;

import com.code_intelligence.jazzer.api.CannedFuzzedDataProvider;
import org.junit.jupiter.api.Test;

import java.nio.charset.StandardCharsets;
import java.util.List;

class CleartextHttp2ServerUpgradeHandlerFuzzerTest {
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

    private static byte[] bytes(String value) {
        return value.getBytes(StandardCharsets.US_ASCII);
    }
}
