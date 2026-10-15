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

class HttpResponseEncoderFuzzerTest {
    private static final int CONTENT_LENGTH = 0;
    private static final int CHUNKED = 1;
    private static final int CLOSE_DELIMITED = 2;

    @Test
    void fullResponse() {
        new Input(true)
            .full(true, 200, "OK Then", CONTENT_LENGTH, List.of("X-A", "1", "X-B", "2 \t"), "hello", List.of())
            .run();
    }

    @Test
    void chunkedResponse() {
        new Input(true)
            .streamed(true, 200, null, CHUNKED, List.of("Content-Type", "text/plain"),
                List.of(true, false), List.of("hello", "", "world"), List.of("X-Checksum", "abc"))
            .run();
    }

    @Test
    void multipleResponses() {
        new Input(true)
            .full(true, 100, null, CONTENT_LENGTH, List.of(), "", List.of())
            .streamed(false, 200, "Fine", CONTENT_LENGTH, List.of("Server", "x"),
                List.of(true), List.of("abc", "def"), List.of())
            .full(true, 299, null, CHUNKED, List.of(), "chunked body", List.of("Expires", "0"))
            .streamedEmptyLast(true, 200, null, CLOSE_DELIMITED, List.of(), List.of(false), List.of("until close"))
            .run();
    }

    @Test
    void noBodyStatus() {
        new Input(true)
            .full(true, 304, null, CONTENT_LENGTH, List.of("ETag", "\"x\""), "ignored", List.of())
            .streamed(true, 204, null, CHUNKED, List.of(), List.of(), List.of("ignored"), List.of("X-T", "1"))
            .full(true, 205, null, CHUNKED, List.of(), "ignored", List.of())
            .full(false, 600, "", CONTENT_LENGTH, List.of(), "", List.of())
            .run();
    }

    @Test
    void invalidHeadersAreSkippedWithValidation() {
        new Input(true)
            .full(true, 200, null, CHUNKED, List.of("Bad Name", "x", "X-A", "\r\ninjected", "X-B", "ok"),
                "body", List.of("Content-Length", "1", "X-T", "\u0000"))
            .run();
    }

    @Test
    void arbitraryHeaderBytes() {
        new Input(false)
            .full(true, 200, "Bad\rReason", CONTENT_LENGTH,
                List.of("X-A\r\nX-B", "\u0000\u00ff\r\n", "", " ", "Content-Length", "-1"), "body", List.of())
            .streamed(true, 101, "Upgrade\u0001", CHUNKED, List.of("Sec-WebSocket-Version", "13"),
                List.of(true), List.of("a", "b"), List.of("Trailer:", "\n"))
            .run();
    }

    @Test
    void switchingProtocolsWithBody() {
        new Input(true)
            .full(true, 101, null, CONTENT_LENGTH, List.of("Upgrade", "foo"), "body", List.of())
            .run();
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

        Input full(boolean http11, int status, String reasonPhrase, int framing, List<String> headers, String body,
                   List<String> trailers) {
            head(http11, status, reasonPhrase, framing, headers);
            shapes.add(true);
            shapes.add(trailers.size() / 2);
            segments.add(body);
            segments.addAll(trailers);
            return this;
        }

        Input streamed(boolean http11, int status, String reasonPhrase, int framing, List<String> headers,
                       List<Boolean> httpContentChunks, List<String> chunks, List<String> trailers) {
            head(http11, status, reasonPhrase, framing, headers);
            shapes.add(false);
            shapes.add(httpContentChunks.size());
            shapes.addAll(httpContentChunks);
            shapes.add(false);
            shapes.add(trailers.size() / 2);
            segments.addAll(chunks);
            segments.addAll(trailers);
            return this;
        }

        Input streamedEmptyLast(boolean http11, int status, String reasonPhrase, int framing, List<String> headers,
                                List<Boolean> httpContentChunks, List<String> chunks) {
            head(http11, status, reasonPhrase, framing, headers);
            shapes.add(false);
            shapes.add(httpContentChunks.size());
            shapes.addAll(httpContentChunks);
            shapes.add(true);
            segments.addAll(chunks);
            return this;
        }

        private void head(boolean http11, int status, String reasonPhrase, int framing, List<String> headers) {
            responseCount++;
            shapes.add(http11);
            shapes.add(status);
            shapes.add(reasonPhrase != null);
            shapes.add(framing);
            shapes.add(headers.size() / 2);
            if (reasonPhrase != null) {
                segments.add(reasonPhrase);
            }
            segments.addAll(headers);
        }

        void run() {
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
            HttpResponseEncoderFuzzer.fuzzerTestOneInput(CannedFuzzedDataProvider.create(values));
        }
    }
}
