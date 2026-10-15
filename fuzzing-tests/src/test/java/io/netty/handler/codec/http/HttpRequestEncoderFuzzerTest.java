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

import java.util.ArrayList;
import java.util.List;

import static java.nio.charset.StandardCharsets.UTF_8;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

class HttpRequestEncoderFuzzerTest {
    private static final int HTTP_1_0 = 0;
    private static final int HTTP_1_1 = 1;
    private static final int CUSTOM_VERSION = 2;

    private static final int CONTENT_LENGTH = 0;
    private static final int CHUNKED = 1;
    private static final int NO_FRAMING = 2;

    private static final int HTTP_CONTENT = 0;
    private static final int BYTE_BUF = 1;
    private static final int EMPTY_BUFFER = 2;

    @Test
    void fullRequest() {
        run(1, new Request(HTTP_1_1, "POST", "/index.html").header("Host", "example.com").header("Accept", "*/*")
            .full("hello"));
    }

    @Test
    void fullChunkedRequestWithTrailers() {
        run(1, new Request(HTTP_1_1, "PUT", "/upload").framing(CHUNKED, 0).header("x-a", "b")
            .full("hello world").trailer("x-checksum", "1234"));
    }

    @Test
    void chunkedRequest() {
        run(1, new Request(HTTP_1_1, "POST", "/stream").framing(CHUNKED, 1).header("Host", "example.com")
            .header("Content-Type", "text/plain")
            .chunk(HTTP_CONTENT, "first").chunk(BYTE_BUF, "second").chunk(EMPTY_BUFFER, null).chunk(HTTP_CONTENT, "")
            .last("last").trailer("x-trailer", "value"));
    }

    @Test
    void streamingContentLengthRequest() {
        run(1, new Request(HTTP_1_0, "POST", "/stream").chunk(HTTP_CONTENT, "abc").chunk(BYTE_BUF, "def")
            .emptyLast());
    }

    @Test
    void severalRequests() {
        run(
            4,
            new Request(HTTP_1_1, "GET", "/a").noise(1).header("Host", "example.com").full(""),
            new Request(HTTP_1_1, "POST", "/b").noise(2).framing(CHUNKED, 0).chunk(HTTP_CONTENT, "body").emptyLast(),
            new Request(HTTP_1_0, "PUT", "/c").chunk(BYTE_BUF, "xyz").last("!"),
            new Request(HTTP_1_1, "DELETE", "/d").full("gone")
        );
    }

    @Test
    void unusualMethodsAndUris() {
        run(
            4,
            new Request(HTTP_1_1, "PROPFIND", "http://example.com?a=b").full(""),
            new Request(HTTP_1_1, "M-SEARCH", "http://example.com").full(""),
            new Request(HTTP_1_1, "OPTIONS", "*").full(""),
            new Request(HTTP_1_1, "GET", "").full("")
        );
        run(
            2,
            new Request(HTTP_1_1, "GET", "/ä€😀?q=Ā").full("x"),
            new Request(CUSTOM_VERSION, "GET", "/custom").version("http/1.1").full(""),
            // the decoder only accepts HTTP/x.y
            new Request(CUSTOM_VERSION, "GET", "/custom").version("ICAP/01.0").full(""),
            // whitespace other than SP passes validation but can't round trip
            new Request(HTTP_1_1, "GET", "/a\tb").full("")
        );
    }

    @Test
    void rejectedRequestLines() {
        run(
            0,
            new Request(CUSTOM_VERSION, "GET", "/").version("HTTP/x").full(""),
            new Request(CUSTOM_VERSION, "GET", "/").version("HT TP/1.1").full(""),
            new Request(HTTP_1_1, "GE T", "/").full(""),
            new Request(HTTP_1_1, "", "/").full("")
        );
        run(
            0,
            new Request(HTTP_1_1, "GET", "/a b").full("body"),
            new Request(HTTP_1_1, "GET", "/a\r\nHost: x").chunk(HTTP_CONTENT, "body").emptyLast()
        );
    }

    @Test
    void validatedHeaderBytes() {
        run(
            2,
            new Request(HTTP_1_1, "POST", "/").framing(CHUNKED, 2)
                .header("x-trailing", "value \t")
                .header("x-latin1", "äÿ")
                .header("x-wide", "ĀĊ")
                .asciiHeader("x-ascii", "vä")
                .header("x-empty", "")
                .chunk(HTTP_CONTENT, "data")
                .last("")
                // rejected and skipped
                .trailer("content-length", "1")
                .trailer("x-ok", "1"),
            // all rejected and skipped
            new Request(HTTP_1_1, "POST", "/")
                .header("x bad", "v")
                .header("x-bad", "v\r\nInjected: 1")
                .header("x-bad", " leading")
                .header("", "v")
                .full("abc")
        );
    }

    @Test
    void arbitraryHeaderBytes() {
        run(
            1,
            // can't round trip
            new Request(HTTP_1_1, "POST", "/").unvalidated()
                .header("x bad\u0000", "v\r\nInjected: 1")
                .asciiHeader("ÿĀ", "\u0000\u007f\u0080")
                .full("abc").trailer("Content-Length", "5"),
            // round trips, since the headers happen to be valid. The decoder drops the prohibited trailer
            new Request(HTTP_1_1, "POST", "/").unvalidated().framing(CHUNKED, 0).header("x-a", "b")
                .full("abc").trailer("Content-Length", "5")
        );
    }

    @Test
    void framingHeadersFromInput() {
        run(
            3,
            // framing headers from the input that match the body
            new Request(HTTP_1_1, "POST", "/").framing(NO_FRAMING, 0).header("Content-Length", "3").full("abc"),
            new Request(HTTP_1_1, "POST", "/").framing(NO_FRAMING, 0).header("Transfer-Encoding", "Chunked")
                .chunk(HTTP_CONTENT, "abc").emptyLast(),
            // no framing and no body
            new Request(HTTP_1_1, "GET", "/").framing(NO_FRAMING, 0).full("")
        );
        run(
            0,
            // conflicting or wrong framing can't round trip
            new Request(HTTP_1_1, "POST", "/").header("transfer-encoding", "chunked").full("abc"),
            new Request(HTTP_1_1, "POST", "/").framing(NO_FRAMING, 0).header("Content-Length", "4").full("abc"),
            new Request(HTTP_1_0, "POST", "/").framing(CHUNKED, 0).full("abc"),
            new Request(HTTP_1_1, "GET", "/").framing(NO_FRAMING, 0).header("Sec-WebSocket-Key1", "1")
                .header("Sec-WebSocket-Key2", "2").full("")
        );
    }

    @Test
    void misplacedMessages() {
        // content, last content, empty last content and a byte buffer before the request
        run(
            4,
            new Request(HTTP_1_1, "GET", "/").misplaced(1).full(""),
            new Request(HTTP_1_1, "GET", "/").misplaced(2).full(""),
            new Request(HTTP_1_1, "GET", "/").misplaced(3).full(""),
            new Request(HTTP_1_1, "GET", "/").misplaced(4).full("")
        );
        // a request or full request before the last content
        run(
            3,
            new Request(HTTP_1_1, "POST", "/").misplaced(5).chunk(HTTP_CONTENT, "abc").emptyLast(),
            new Request(HTTP_1_1, "POST", "/").misplaced(6).framing(CHUNKED, 0).chunk(BYTE_BUF, "abc").last("d"),
            // ignored for full requests
            new Request(HTTP_1_1, "POST", "/").misplaced(6).full("abc")
        );
    }

    /**
     * Run the requests on one channel.
     *
     * @param expectedRoundTrips The number of requests that the fuzzer should check by decoding them again
     * @param requests The requests
     */
    private static void run(int expectedRoundTrips, Request... requests) {
        // CannedFuzzedDataProvider does not check ranges, so check that the input is one the fuzzer can generate
        assertTrue(requests.length <= HttpRequestEncoderFuzzer.MAX_REQUESTS);
        List<Object> values = new ArrayList<>();
        values.add(requests.length);
        for (Request request : requests) {
            request.appendTo(values);
        }
        assertEquals(expectedRoundTrips, HttpRequestEncoderFuzzer.fuzz(CannedFuzzedDataProvider.create(values)));
    }

    private static final class Request {
        private final int versionChoice;
        private final String method;
        private final String uri;
        private String versionText;
        private int noise;
        private int misplaced;
        private boolean validate = true;
        private int framing = CONTENT_LENGTH;
        private int framingPosition;
        private final List<Object> headers = new ArrayList<>();
        private int headerCount;
        private final List<Object> trailers = new ArrayList<>();
        private int trailerCount;
        private final List<Object> body = new ArrayList<>();
        private int chunkCount;
        private boolean full;
        private boolean hasTrailers;

        Request(int versionChoice, String method, String uri) {
            this.versionChoice = versionChoice;
            this.method = method;
            this.uri = uri;
        }

        Request version(String text) {
            versionText = text;
            return this;
        }

        Request noise(int noise) {
            this.noise = noise;
            return this;
        }

        Request misplaced(int misplaced) {
            this.misplaced = misplaced;
            return this;
        }

        Request unvalidated() {
            validate = false;
            return this;
        }

        Request framing(int framing, int position) {
            this.framing = framing;
            this.framingPosition = position;
            return this;
        }

        Request header(String name, String value) {
            return addHeader(name, value, false);
        }

        Request asciiHeader(String name, String value) {
            return addHeader(name, value, true);
        }

        private Request addHeader(String name, String value, boolean ascii) {
            headers.addAll(List.of(name, ascii, value, ascii));
            headerCount++;
            assertTrue(headerCount <= HttpRequestEncoderFuzzer.MAX_HEADERS);
            return this;
        }

        Request trailer(String name, String value) {
            trailers.addAll(List.of(name, false, value, false));
            trailerCount++;
            assertTrue(trailerCount <= HttpRequestEncoderFuzzer.MAX_TRAILERS);
            return this;
        }

        Request full(String content) {
            full = true;
            hasTrailers = true;
            body.add(content.getBytes(UTF_8));
            return this;
        }

        Request chunk(int kind, String content) {
            body.add(kind);
            if (kind != EMPTY_BUFFER) {
                body.add(content.getBytes(UTF_8));
            }
            chunkCount++;
            assertTrue(chunkCount <= HttpRequestEncoderFuzzer.MAX_CHUNKS);
            return this;
        }

        Request last(String content) {
            body.add(true);
            body.add(content.getBytes(UTF_8));
            hasTrailers = true;
            return this;
        }

        Request emptyLast() {
            body.add(false);
            return this;
        }

        void appendTo(List<Object> values) {
            values.add(noise);
            values.add(misplaced);
            values.add(versionChoice);
            if (versionChoice == CUSTOM_VERSION) {
                values.add(versionText);
            }
            values.add(method);
            values.add(uri);
            values.add(validate);
            values.add(full);
            values.add(framing);
            values.add(headerCount);
            values.add(Math.min(framingPosition, headerCount));
            values.addAll(headers);
            if (!full) {
                values.add(chunkCount);
            }
            values.addAll(body);
            if (hasTrailers) {
                values.add(trailerCount);
                values.addAll(trailers);
            }
        }
    }
}
