package io.netty.handler.codec.base64;

import com.code_intelligence.jazzer.api.CannedFuzzedDataProvider;
import org.junit.jupiter.api.Test;

import java.util.List;

import static java.nio.charset.StandardCharsets.US_ASCII;

class Base64EncoderFuzzerTest {
    @Test
    void fuzzesStandardDialectPayload() {
        Base64EncoderFuzzer.fuzzerTestOneInput(CannedFuzzedDataProvider.create(List.of(
            false,
            0,
            "hello".getBytes(US_ASCII)
        )));
    }

    @Test
    void fuzzesUrlSafeDialectWithLineBreaks() {
        Base64EncoderFuzzer.fuzzerTestOneInput(CannedFuzzedDataProvider.create(List.of(
            true,
            1,
            "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789".getBytes(US_ASCII)
        )));
    }
}
