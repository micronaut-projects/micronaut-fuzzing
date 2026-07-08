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

import com.code_intelligence.jazzer.api.FuzzedDataProvider;
import io.micronaut.fuzzing.Dict;
import io.micronaut.fuzzing.FlagAppender;
import io.micronaut.fuzzing.FuzzTarget;
import io.micronaut.fuzzing.HttpDict;
import io.micronaut.fuzzing.runner.LocalJazzerRunner;
import io.micronaut.fuzzing.util.ByteSplitter;
import io.netty.buffer.ByteBuf;
import io.netty.channel.embedded.EmbeddedChannel;
import io.netty.util.LeakPresenceDetector;
import io.netty.util.ReferenceCountUtil;
import io.netty.util.concurrent.FastThreadLocalThread;

/**
 * Fuzzing support type.
 */
@FuzzTarget
@HttpDict
@Dict({
    "gzip",
    "deflate",
    "br",
    "zstd",
    "snappy",
    "identity",
    "*",
    ";q=",
    ", ",
    "SEP",
    "gzip, deflate, br",
    "br;q=1.0, gzip;q=0.8, *;q=0.1",
    "zstd;q=0.9, snappy;q=0.5, identity;q=0"
})
public final class HttpContentCompressorFuzzer {
    private static final ByteSplitter SPLITTER = ByteSplitter.create("SEP");
    private static final int MAX_ACCEPT_ENCODING_LENGTH = 128;
    private static final int MAX_BODY_LENGTH = 4096;

    private static final HttpMethod[] METHODS = {
        HttpMethod.GET,
        HttpMethod.POST,
        HttpMethod.HEAD,
        HttpMethod.CONNECT
    };

    private static final int[] RESPONSE_CODES = {
        100,
        101,
        200,
        201,
        204,
        206,
        304,
        400,
        500
    };

    public static void fuzzerTestOneInput(FuzzedDataProvider fuzzedDataProvider) {
        byte[] body = fuzzedDataProvider.consumeBytes(fuzzedDataProvider.consumeInt(0, MAX_BODY_LENGTH));
        FastThreadLocalThread.runWithFastThreadLocal(() -> test(fuzzedDataProvider, body));
    }

    private static void test(FuzzedDataProvider data, byte[] body) {
        EmbeddedChannel channel = new EmbeddedChannel(new HttpContentCompressor());
        try {
            writeRequest(data, channel);
            drain(channel);

            writeResponse(data, channel, body.length);
            writeContent(channel, body);
            channel.finish();
        } finally {
            drain(channel);
            channel.releaseInbound();
            channel.releaseOutbound();
            LeakPresenceDetector.check();
            FlagAppender.checkTriggered();
        }
    }

    private static void writeRequest(FuzzedDataProvider data, EmbeddedChannel channel) {
        HttpMethod method = data.pickValue(METHODS);
        DefaultHttpRequest request = new DefaultHttpRequest(HttpVersion.HTTP_1_1, method, "/");
        request.headers().add(HttpHeaderNames.ACCEPT_ENCODING, acceptEncoding(data));
        if (data.consumeBoolean()) {
            request.headers().add(HttpHeaderNames.ACCEPT_ENCODING, acceptEncoding(data));
        }
        channel.writeInbound(request);
    }

    private static String acceptEncoding(FuzzedDataProvider data) {
        return sanitizeHeaderValue(data.consumeString(MAX_ACCEPT_ENCODING_LENGTH));
    }

    private static String sanitizeHeaderValue(String value) {
        StringBuilder builder = new StringBuilder(value.length());
        for (int i = 0; i < value.length() && builder.length() < MAX_ACCEPT_ENCODING_LENGTH; i++) {
            char c = value.charAt(i);
            if (c >= 0x20 && c <= 0x7e) {
                builder.append(c);
            }
        }
        String headerValue = builder.toString().trim();
        if (headerValue.isEmpty()) {
            return "gzip";
        }
        return headerValue;
    }

    private static void writeResponse(FuzzedDataProvider data, EmbeddedChannel channel, int bodyLength) {
        HttpResponseStatus status = HttpResponseStatus.valueOf(data.pickValue(RESPONSE_CODES));
        DefaultHttpResponse response = new DefaultHttpResponse(HttpVersion.HTTP_1_1, status);
        if (data.consumeBoolean()) {
            response.headers().set(HttpHeaderNames.CONTENT_LENGTH, bodyLength);
        }
        if (data.consumeBoolean()) {
            response.headers().set(HttpHeaderNames.CONTENT_TYPE, "application/octet-stream");
        }
        if (data.consumeBoolean()) {
            response.headers().set(HttpHeaderNames.CONTENT_ENCODING, sanitizeHeaderValue(data.consumeString(MAX_ACCEPT_ENCODING_LENGTH)));
        }
        channel.writeOutbound(response);
    }

    private static void writeContent(EmbeddedChannel channel, byte[] body) {
        ByteSplitter.ChunkIterator chunks = SPLITTER.splitIterator(body);
        while (chunks.hasNext()) {
            chunks.proceed();
            ByteBuf content = buffer(channel, body, chunks.start(), chunks.length());
            if (chunks.hasNext()) {
                writeOutbound(channel, new DefaultHttpContent(content));
            } else {
                writeOutbound(channel, new DefaultLastHttpContent(content));
            }
        }
    }

    private static ByteBuf buffer(EmbeddedChannel channel, byte[] body, int offset, int length) {
        ByteBuf buffer = channel.alloc().buffer(length);
        buffer.writeBytes(body, offset, length);
        return buffer;
    }

    private static void writeOutbound(EmbeddedChannel channel, HttpObject message) {
        boolean written = false;
        try {
            channel.writeOutbound(message);
            written = true;
        } finally {
            if (!written) {
                ReferenceCountUtil.release(message);
            }
        }
    }

    private static void drain(EmbeddedChannel channel) {
        Object message;
        while ((message = channel.readInbound()) != null) {
            ReferenceCountUtil.release(message);
        }
        while ((message = channel.readOutbound()) != null) {
            ReferenceCountUtil.release(message);
        }
    }

    public static void main(String[] args) {
        LocalJazzerRunner.create(HttpContentCompressorFuzzer.class).fuzz();
    }
}
