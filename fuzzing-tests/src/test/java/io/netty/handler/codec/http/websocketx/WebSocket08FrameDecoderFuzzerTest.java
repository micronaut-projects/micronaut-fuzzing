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
package io.netty.handler.codec.http.websocketx;

import com.code_intelligence.jazzer.api.CannedFuzzedDataProvider;
import org.junit.jupiter.api.Test;

import java.io.ByteArrayOutputStream;
import java.util.Arrays;
import java.util.List;

import static io.micronaut.fuzzing.EmbeddedChannelFuzzerBase.SEPARATOR;
import static java.nio.charset.StandardCharsets.UTF_8;

class WebSocket08FrameDecoderFuzzerTest {
    private static final byte[] MASK = { 1, 2, 3, 4 };

    @Test
    void fuzzesMaskedTextFrame() throws Exception {
        WebSocket08FrameDecoderFuzzer.fuzzerTestOneInput(CannedFuzzedDataProvider.create(List.of(
            true,
            false,
            false,
            true,
            true,
            1024,
            frame(true, 1, true, "hello".getBytes(UTF_8))
        )));
    }

    @Test
    void fuzzesFragmentedBinaryFrames() throws Exception {
        WebSocket08FrameDecoderFuzzer.fuzzerTestOneInput(CannedFuzzedDataProvider.create(List.of(
            true,
            false,
            false,
            true,
            false,
            1024,
            chunks(
                frame(false, 2, true, bytes('a', 126)),
                frame(true, 0, true, bytes('b', 4))
            )
        )));
    }

    @Test
    void handlesMaskProtocolViolation() throws Exception {
        WebSocket08FrameDecoderFuzzer.fuzzerTestOneInput(CannedFuzzedDataProvider.create(List.of(
            true,
            false,
            false,
            false,
            true,
            1024,
            frame(true, 9, false, "ping".getBytes(UTF_8))
        )));
    }

    private static byte[] frame(boolean finalFragment, int opcode, boolean masked, byte[] payload) {
        ByteArrayOutputStream result = new ByteArrayOutputStream();
        result.write((finalFragment ? 0x80 : 0) | opcode);
        if (payload.length <= 125) {
            result.write((masked ? 0x80 : 0) | payload.length);
        } else {
            result.write((masked ? 0x80 : 0) | 126);
            result.write(payload.length >>> 8);
            result.write(payload.length);
        }
        if (masked) {
            result.writeBytes(MASK);
            for (int i = 0; i < payload.length; i++) {
                result.write(payload[i] ^ MASK[i % MASK.length]);
            }
        } else {
            result.writeBytes(payload);
        }
        return result.toByteArray();
    }

    private static byte[] bytes(char value, int length) {
        byte[] result = new byte[length];
        Arrays.fill(result, (byte) value);
        return result;
    }

    private static byte[] chunks(byte[] firstChunk, byte[] secondChunk) {
        ByteArrayOutputStream result = new ByteArrayOutputStream();
        result.writeBytes(firstChunk);
        result.writeBytes(SEPARATOR.getBytes(UTF_8));
        result.writeBytes(secondChunk);
        return result.toByteArray();
    }
}
