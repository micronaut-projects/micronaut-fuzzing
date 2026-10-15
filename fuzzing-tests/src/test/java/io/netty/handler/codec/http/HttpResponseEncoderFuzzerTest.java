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
import org.junit.jupiter.api.Test;

import java.io.ByteArrayOutputStream;
import java.util.ArrayList;
import java.util.List;

import static java.nio.charset.StandardCharsets.ISO_8859_1;
import static org.junit.jupiter.api.Assertions.assertEquals;

class HttpResponseEncoderFuzzerTest {
    private static final int CONTENT_LENGTH = 0;
    private static final int CHUNKED = 1;
    private static final int CLOSE_DELIMITED = 2;

    private static final List<Object> HTTP_1_0 = List.of(0);
    private static final List<Object> HTTP_1_1 = List.of(1);

    private static List<Object> customVersion(int major, int minor) {
        return List.of(2, major, minor, true);
    }

    @Test
    void fullResponse() {
        new Input(true)
            .full(HTTP_1_1, 200, "OK Then", CONTENT_LENGTH, List.of("X-A", "1", "X-B", "2 \t"), "hello", List.of())
            .run(1);
    }

    @Test
    void chunkedResponse() {
        new Input(true)
            .streamed(HTTP_1_1, 200, null, CHUNKED, List.of("Content-Type", "text/plain"),
                List.of(true, false), List.of("hello", "", "world"), List.of("X-Checksum", "abc"))
            .run(1);
    }

    @Test
    void multipleResponses() {
        new Input(true)
            .full(HTTP_1_1, 100, null, CONTENT_LENGTH, List.of(), "", List.of())
            .streamed(HTTP_1_0, 200, "Fine", CONTENT_LENGTH, List.of("Server", "x"),
                List.of(true), List.of("abc", "def"), List.of())
            .full(HTTP_1_1, 299, null, CHUNKED, List.of(), "chunked body", List.of("Expires", "0"))
            .streamedEmptyLast(HTTP_1_1, 200, null, CLOSE_DELIMITED, List.of(), List.of(false), List.of("until close"))
            .run(4);
    }

    @Test
    void noBodyStatus() {
        // framing that would be ambiguous with a body does not matter for these statuses
        new Input(true)
            .full(HTTP_1_0, 304, null, CHUNKED, List.of("ETag", "\"x\""), "ignored", List.of())
            .streamed(HTTP_1_1, 204, null, CLOSE_DELIMITED, List.of(), List.of(), List.of("ignored"), List.of("X-T", "1"))
            .full(HTTP_1_1, 205, null, CHUNKED, List.of(), "ignored", List.of())
            .full(HTTP_1_1, 600, "", CONTENT_LENGTH, List.of(), "", List.of())
            .run(4);
    }

    @Test
    void invalidHeadersAreSkippedWithValidation() {
        new Input(true)
            .full(HTTP_1_1, 200, null, CHUNKED, List.of("Bad Name", "x", "X-A", "\r\ninjected", "X-B", "ok"),
                "body", List.of("Content-Length", "1", "X-T", "\u0000"))
            .run(1);
    }

    @Test
    void unusualReasonPhraseIsReplacedWithValidation() {
        new Input(true)
            .full(HTTP_1_1, 200, " odd\u0001\u00ff ", CONTENT_LENGTH, List.of(), "body", List.of())
            .run(1);
    }

    @Test
    void wellFormedHeadersWithoutValidation() {
        new Input(false)
            .full(HTTP_1_1, 200, "OK", CONTENT_LENGTH, List.of("X-A", "1"), "body", List.of())
            .run(1);
    }

    @Test
    void customVersionAndStatus() {
        new Input(true)
            .full(customVersion(0, 9), 42, null, CONTENT_LENGTH, List.of(), "body", List.of())
            .full(customVersion(1, 1), 1042, "Big", CHUNKED, List.of(), "body", List.of())
            .full(customVersion(2, 0), 0, null, CLOSE_DELIMITED, List.of(), "body", List.of())
            .run(3);
    }

    @Test
    void arbitraryHeaderBytes() {
        new Input(false)
            .full(HTTP_1_1, 200, "Bad\rReason", CONTENT_LENGTH,
                List.of("X-A\r\nX-B", "\u0000\u00ff\r\n", "", " ", "Content-Length", "-1"), "body", List.of())
            .streamed(HTTP_1_1, 101, "Upgrade\u0001", CHUNKED, List.of("Sec-WebSocket-Version", "13"),
                List.of(true), List.of("a", "b"), List.of("Trailer:", "\n"))
            .run(0);
    }

    @Test
    void switchingProtocolsWithBody() {
        new Input(true)
            .full(HTTP_1_1, 101, null, CONTENT_LENGTH, List.of("Upgrade", "foo"), "body", List.of())
            .run(0);
    }

    /**
     * Builds the {@link CannedFuzzedDataProvider} values in the order in which the fuzzer consumes them.
     */
    private static final class Input {
        private final boolean validate;
        private final List<Object> shapes = new ArrayList<>();
        private final List<String> segments = new ArrayList<>();
        private int responseCount;

        Input(boolean validate) {
            this.validate = validate;
        }

        Input full(List<Object> version, int status, String reasonPhrase, int framing, List<String> headers, String body,
                   List<String> trailers) {
            head(version, status, reasonPhrase, framing, headers);
            shapes.add(true);
            shapes.add(trailers.size() / 2);
            segments.add(body);
            segments.addAll(trailers);
            return this;
        }

        Input streamed(List<Object> version, int status, String reasonPhrase, int framing, List<String> headers,
                       List<Boolean> httpContentChunks, List<String> chunks, List<String> trailers) {
            head(version, status, reasonPhrase, framing, headers);
            shapes.add(false);
            shapes.add(httpContentChunks.size());
            shapes.addAll(httpContentChunks);
            shapes.add(false);
            shapes.add(trailers.size() / 2);
            segments.addAll(chunks);
            segments.addAll(trailers);
            return this;
        }

        Input streamedEmptyLast(List<Object> version, int status, String reasonPhrase, int framing, List<String> headers,
                                List<Boolean> httpContentChunks, List<String> chunks) {
            head(version, status, reasonPhrase, framing, headers);
            shapes.add(false);
            shapes.add(httpContentChunks.size());
            shapes.addAll(httpContentChunks);
            shapes.add(true);
            segments.addAll(chunks);
            return this;
        }

        private void head(List<Object> version, int status, String reasonPhrase, int framing, List<String> headers) {
            responseCount++;
            shapes.addAll(version);
            shapes.add(status);
            shapes.add(reasonPhrase != null);
            shapes.add(framing);
            shapes.add(headers.size() / 2);
            if (reasonPhrase != null) {
                segments.add(reasonPhrase);
            }
            segments.addAll(headers);
        }

        void run(int expectedRoundTrips) {
            List<Object> values = new ArrayList<>();
            values.add(validate);
            values.add(responseCount);
            values.addAll(shapes);
            ByteArrayOutputStream remaining = new ByteArrayOutputStream();
            for (int i = 0; i < segments.size(); i++) {
                if (i != 0) {
                    remaining.writeBytes("SEP".getBytes(ISO_8859_1));
                }
                remaining.writeBytes(segments.get(i).getBytes(ISO_8859_1));
            }
            values.add(remaining.toByteArray());
            int roundTrips = HttpResponseEncoderFuzzer.testOneInput(CannedFuzzedDataProvider.create(values));
            assertEquals(expectedRoundTrips, roundTrips, "responses checked by the round trip oracle");
        }
    }
}
