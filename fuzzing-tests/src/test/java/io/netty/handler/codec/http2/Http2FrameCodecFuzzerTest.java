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
package io.netty.handler.codec.http2;

import com.code_intelligence.jazzer.api.CannedFuzzedDataProvider;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;

import java.util.HexFormat;
import java.util.List;

class Http2FrameCodecFuzzerTest {
    // empty SETTINGS frame, the server preface
    private static final String SETTINGS = "000000" + "04" + "00" + "00000000";
    // HEADERS on server stream 2, END_HEADERS, ":status: 200"
    private static final String HEADERS_STREAM_2 = "000001" + "01" + "04" + "00000002" + "88";
    // DATA on stream 2, END_STREAM, 3 bytes
    private static final String DATA_STREAM_2 = "000003" + "00" + "01" + "00000002" + "010203";
    // PUSH_PROMISE on stream 2 for stream 4, END_HEADERS, GET https://a/x
    private static final String PUSH_PROMISE_HEADER = "05" + "04" + "00000002" + "00000004" + "828744022f78410161";
    private static final String PUSH_PROMISE = "00000d" + PUSH_PROMISE_HEADER;
    // the same, with "content-length: abc"
    private static final String PUSH_PROMISE_INVALID_CONTENT_LENGTH = "000012" + PUSH_PROMISE_HEADER + "5c03616263";
    // DATA on the reserved stream 4, 3 bytes
    private static final String DATA_STREAM_4 = "000003" + "00" + "00" + "00000004" + "010203";

    @Test
    void headersAndData() {
        fuzz(SETTINGS + HEADERS_STREAM_2 + DATA_STREAM_2);
    }

    @Test
    void retryOnSameInstance() {
        Http2FrameCodecFuzzer fuzzer = new Http2FrameCodecFuzzer();
        fuzzer.test(input(SETTINGS + HEADERS_STREAM_2 + DATA_STREAM_2));
        fuzzer.test(input(SETTINGS + HEADERS_STREAM_2 + DATA_STREAM_2));
    }

    @Test
    void pushPromiseWithInvalidContentLength() {
        fuzz(SETTINGS + HEADERS_STREAM_2 + PUSH_PROMISE_INVALID_CONTENT_LENGTH);
    }

    @Test
    void dataOnReservedStream() {
        fuzz(SETTINGS + HEADERS_STREAM_2 + PUSH_PROMISE + DATA_STREAM_4);
    }

    @Test
    void otherContentLengthExceptionIsReported() {
        IllegalArgumentException e = new IllegalArgumentException("Content-Length value is not a number: abc");
        e.setStackTrace(new StackTraceElement[]{
            new StackTraceElement("io.netty.handler.codec.http.HttpUtil", "normalizeAndGetContentLength", null, -1),
            new StackTraceElement("io.netty.handler.codec.http2.DefaultHttp2ConnectionDecoder$FrameReadListener", "onHeadersRead", null, -1)
        });
        Assertions.assertThrows(IllegalArgumentException.class, () -> new Http2FrameCodecFuzzer().onException(e));
    }

    @Test
    void otherFlowControlExceptionIsReported() {
        UnsupportedOperationException e = new UnsupportedOperationException();
        e.setStackTrace(new StackTraceElement[]{
            new StackTraceElement("io.netty.handler.codec.http2.DefaultHttp2LocalFlowController$2", "writeWindowUpdateIfNeeded", null, -1),
            new StackTraceElement("io.netty.handler.codec.http2.DefaultHttp2LocalFlowController", "consumeBytes", null, -1)
        });
        Assertions.assertThrows(UnsupportedOperationException.class, () -> new Http2FrameCodecFuzzer().onException(e));
    }

    private static void fuzz(String hex) {
        Http2FrameCodecFuzzer.fuzzerTestOneInput(input(hex));
    }

    private static CannedFuzzedDataProvider input(String hex) {
        return CannedFuzzedDataProvider.create(List.<Object>of(HexFormat.of().parseHex(hex)));
    }
}
