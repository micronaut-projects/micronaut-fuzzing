package io.netty.handler.codec.http.websocketx;

import com.code_intelligence.jazzer.api.CannedFuzzedDataProvider;
import org.junit.jupiter.api.Test;

import java.util.List;

import static java.nio.charset.StandardCharsets.UTF_8;

class WebSocketFrameAggregatorFuzzerTest {
    private static final int TEXT = 1;
    private static final int FINAL_TEXT = 0x80 | TEXT;
    private static final int BINARY = 2;
    private static final int FINAL_BINARY = 0x80 | BINARY;
    private static final int PING_FINAL = 0x80 | 9;
    private static final int PONG_FINAL = 0x80 | 10;
    private static final int CLOSE_FINAL = 0x80 | 8;
    private static final int CONTINUATION = 0;
    private static final int FINAL_CONTINUATION = 0x80;
    private static final int RSV1_FINAL_TEXT = 0xc0 | TEXT;

    @Test
    void fuzzesFragmentedFramesWithInterleavedControlFrame() throws Exception {
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
    void handlesOversizedAggregatesAsExpectedNettyValidation() throws Exception {
        WebSocketFrameAggregatorFuzzer.fuzzerTestOneInput(CannedFuzzedDataProvider.create(List.of(
            4,
            frames(
                frame(TEXT, "test"),
                frame(FINAL_CONTINUATION, "!")
            )
        )));
    }

    @Test
    void fuzzesFragmentedBinaryFrames() throws Exception {
        WebSocketFrameAggregatorFuzzer.fuzzerTestOneInput(CannedFuzzedDataProvider.create(List.of(
            16,
            frames(
                frame(BINARY, new byte[] { 1 }),
                frame(CONTINUATION, new byte[] { 2 }),
                frame(FINAL_CONTINUATION, new byte[] { 3 })
            )
        )));
    }

    @Test
    void fuzzesSingleFinalTextFrame() throws Exception {
        WebSocketFrameAggregatorFuzzer.fuzzerTestOneInput(CannedFuzzedDataProvider.create(List.of(
            16,
            frame(FINAL_TEXT, "hello")
        )));
    }

    @Test
    void decoderReplacementCanReachOldFrameCategories() throws Exception {
        WebSocketFrameAggregatorFuzzer.fuzzerTestOneInput(CannedFuzzedDataProvider.create(List.of(
            16,
            frames(
                frame(FINAL_TEXT, "text"),
                frame(FINAL_BINARY, new byte[] { 1, 2, 3 }),
                frame(PING_FINAL, new byte[] { 4 }),
                frame(PONG_FINAL, new byte[] { 5 }),
                closeFrame()
            )
        )));
    }

    @Test
    void decoderReplacementCanReachRsvPathsAllowedByExtensions() throws Exception {
        WebSocketFrameAggregatorFuzzer.fuzzerTestOneInput(CannedFuzzedDataProvider.create(List.of(
            16,
            frame(RSV1_FINAL_TEXT, "reserved")
        )));
    }

    @Test
    void decoderReplacementCanAggregateRsvFragmentedFrames() throws Exception {
        WebSocketFrameAggregatorFuzzer.fuzzerTestOneInput(CannedFuzzedDataProvider.create(List.of(
            16,
            frames(
                frame(0x40 | TEXT, "reserved"),
                frame(FINAL_CONTINUATION, " continuation")
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
        byte[] frame = new byte[payload.length + 2];
        frame[0] = (byte) descriptor;
        frame[1] = (byte) payload.length;
        System.arraycopy(payload, 0, frame, 2, payload.length);
        return frame;
    }

    private static byte[] closeFrame() {
        return frame(CLOSE_FINAL, new byte[] { 3, (byte) 232 });
    }
}
