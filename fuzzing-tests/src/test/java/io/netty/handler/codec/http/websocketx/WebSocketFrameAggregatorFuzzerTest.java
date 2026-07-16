package io.netty.handler.codec.http.websocketx;

import com.code_intelligence.jazzer.api.CannedFuzzedDataProvider;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;

import java.util.List;

import static java.nio.charset.StandardCharsets.UTF_8;

class WebSocketFrameAggregatorFuzzerTest {
    private static final int TEXT = 0;
    private static final int PING_FINAL = 3 << 4 | 1;
    private static final int CONTINUATION = 2 << 4;
    private static final int FINAL_CONTINUATION = 2 << 4 | 1;

    @BeforeAll
    static void configureLeakDetector() {
        System.setProperty("io.netty.customResourceLeakDetector", "io.netty.util.LeakPresenceDetector");
    }

    @Test
    void fuzzesFragmentedFramesWithInterleavedControlFrame() {
        WebSocketFrameAggregatorFuzzer.fuzzerTestOneInput(CannedFuzzedDataProvider.create(List.of(
            16,
            frames(
                frame(TEXT, "hello"),
                frame(PING_FINAL, new byte[] { 1 }),
                frame(CONTINUATION, " world"),
                frame(FINAL_CONTINUATION, "!")
            )
        )));
    }

    @Test
    void handlesOversizedAggregatesAsExpectedNettyValidation() {
        WebSocketFrameAggregatorFuzzer.fuzzerTestOneInput(CannedFuzzedDataProvider.create(List.of(
            4,
            frames(
                frame(TEXT, "test"),
                frame(FINAL_CONTINUATION, "!")
            )
        )));
    }

    private static byte[] frames(byte[]... frames) {
        byte[] separator = "SEP".getBytes(UTF_8);
        int length = Math.max(0, frames.length - 1) * separator.length;
        for (byte[] frame : frames) {
            length += frame.length;
        }

        byte[] result = new byte[length];
        int offset = 0;
        for (int i = 0; i < frames.length; i++) {
            System.arraycopy(frames[i], 0, result, offset, frames[i].length);
            offset += frames[i].length;
            if (i != frames.length - 1) {
                System.arraycopy(separator, 0, result, offset, separator.length);
                offset += separator.length;
            }
        }
        return result;
    }

    private static byte[] frame(int descriptor, String payload) {
        return frame(descriptor, payload.getBytes(UTF_8));
    }

    private static byte[] frame(int descriptor, byte[] payload) {
        byte[] frame = new byte[payload.length + 1];
        frame[0] = (byte) descriptor;
        System.arraycopy(payload, 0, frame, 1, payload.length);
        return frame;
    }
}
