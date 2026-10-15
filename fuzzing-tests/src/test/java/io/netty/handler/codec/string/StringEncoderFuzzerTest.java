package io.netty.handler.codec.string;

import com.code_intelligence.jazzer.api.CannedFuzzedDataProvider;
import org.junit.jupiter.api.Test;

import java.util.List;

class StringEncoderFuzzerTest {
    @Test
    void fuzzesUtf8StringInput() {
        StringEncoderFuzzer.fuzzerTestOneInput(CannedFuzzedDataProvider.create(List.of(
            "UTF-8",
            "hello",
            0
        )));
    }

    @Test
    void fuzzesAsciiStringBuilderInput() {
        StringEncoderFuzzer.fuzzerTestOneInput(CannedFuzzedDataProvider.create(List.of(
            "US-ASCII",
            "line\r\nbreak",
            1
        )));
    }

    @Test
    void fuzzesUtf16CharBufferInput() {
        StringEncoderFuzzer.fuzzerTestOneInput(CannedFuzzedDataProvider.create(List.of(
            "UTF-16",
            "foobar",
            2
        )));
    }

    @Test
    void ignoresUnsupportedCharsetNames() {
        StringEncoderFuzzer.fuzzerTestOneInput(CannedFuzzedDataProvider.create(List.of(
            "not-a-real-charset"
        )));
    }

    @Test
    void ignoresEmptyInputAsExpectedNettyValidation() {
        StringEncoderFuzzer.fuzzerTestOneInput(CannedFuzzedDataProvider.create(List.of(
            "UTF-8",
            "",
            0
        )));
    }
}
