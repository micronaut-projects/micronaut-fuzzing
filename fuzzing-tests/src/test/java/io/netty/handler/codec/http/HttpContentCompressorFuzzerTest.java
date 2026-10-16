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

class HttpContentCompressorFuzzerTest {
    private static final int GET = 0;
    private static final int POST = 1;
    private static final int HEAD = 2;
    private static final int CONNECT = 3;

    private static final byte[] CHUNKED_BODY = "hello hello helloSEPworld world worldSEP!".getBytes(UTF_8);

    @Test
    void gzipChunkedContent() {
        run(0, GET, List.of("gzip"), false, 200, false, true, null, CHUNKED_BODY);
    }

    @Test
    void preferredEncodingFullResponse() {
        run(0, POST, List.of("br;q=1.0, gzip;q=0.8, *;q=0.1"), false, 200, true, true, null, CHUNKED_BODY);
    }

    @Test
    void multipleAcceptEncodingHeadersFullResponseWithoutContentLength() {
        run(0, GET, List.of("zstd;q=0.9", "deflate;q=0.5"), false, 201, true, false, null, CHUNKED_BODY);
    }

    @Test
    void snappyChunkedContent() {
        run(0, GET, List.of("snappy"), false, 200, false, false, null, CHUNKED_BODY);
    }

    @Test
    void acceptEncodingThatSelectsNoEncoding() {
        run(0, GET, List.of("identity, compress"), false, 200, false, true, null, CHUNKED_BODY);
    }

    @Test
    void noAcceptEncodingHeader() {
        run(0, GET, List.of(), false, 200, true, true, null, CHUNKED_BODY);
    }

    @Test
    void responseWithoutContent() {
        run(0, GET, List.of("gzip"), false, 204, false, false, null, new byte[0]);
        run(0, GET, List.of("gzip"), false, 200, true, true, null, new byte[0]);
        run(0, GET, List.of("gzip"), false, 200, false, false, null, new byte[0]);
    }

    @Test
    void passThroughCases() {
        // HEAD, CONNECT, 1xx, HTTP/1.0, preset Content-Encoding and content below the size threshold
        run(0, HEAD, List.of("gzip"), false, 200, false, true, null, CHUNKED_BODY);
        run(0, CONNECT, List.of("gzip"), false, 200, false, false, null, CHUNKED_BODY);
        run(0, GET, List.of("gzip"), false, 100, false, false, null, CHUNKED_BODY);
        run(0, GET, List.of("gzip"), true, 200, false, true, null, CHUNKED_BODY);
        run(0, GET, List.of("gzip"), false, 200, false, true, "br", CHUNKED_BODY);
        run(64, GET, List.of("gzip"), false, 200, true, true, null, CHUNKED_BODY);
    }

    @Test
    void headerValueIsSanitized() {
        run(0, GET, List.of(" \u0000gz\ripĀ "), false, 200, false, false, null, CHUNKED_BODY);
    }

    private static void run(
        int contentSizeThreshold,
        int method,
        List<String> acceptEncodings,
        boolean http10,
        int status,
        boolean fullResponse,
        boolean contentLength,
        String contentEncoding,
        byte[] body
    ) {
        List<Object> values = new ArrayList<>();
        values.add(contentSizeThreshold);
        values.add(method);
        values.add(acceptEncodings.size());
        values.addAll(acceptEncodings);
        values.add(http10);
        values.add(status);
        values.add(fullResponse);
        values.add(contentLength);
        values.add(contentEncoding != null);
        if (contentEncoding != null) {
            values.add(contentEncoding);
        }
        values.add(body);
        HttpContentCompressorFuzzer.fuzzerTestOneInput(CannedFuzzedDataProvider.create(values));
    }
}
