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
import io.micronaut.fuzzing.FuzzTarget;
import io.micronaut.fuzzing.runner.LocalJazzerRunner;
import io.netty.buffer.ByteBuf;
import io.netty.buffer.Unpooled;
import io.netty.channel.embedded.EmbeddedChannel;

/**
 * Fuzzing support type.
 */
@FuzzTarget
public class HttpRequestEncoderFuzzer {
    private static final int MAX_HEADER_COUNT = 16;
    private static final int MAX_HEADER_NAME_LENGTH = 64;
    private static final int MAX_HEADER_VALUE_LENGTH = 256;
    private static final int MAX_BODY_LENGTH = 4096;

    public static void fuzzerTestOneInput(FuzzedDataProvider fuzzedDataProvider) throws Exception {
        EmbeddedChannel channel = new EmbeddedChannel(new HttpRequestEncoder());
        try {
            writeRequest(channel, fuzzedDataProvider);
            channel.flushOutbound();
        } finally {
            channel.finishAndReleaseAll();
        }
    }

    private static void writeRequest(EmbeddedChannel channel, FuzzedDataProvider data) {
        int scenario = data.consumeInt(0, 2);
        switch (scenario) {
            case 0 -> writeInitialRequest(channel, data);
            case 1 -> writeFullRequest(channel, data);
            case 2 -> writeChunkedRequest(channel, data);
            default -> throw new IllegalStateException("Unexpected request encoder scenario: " + scenario);
        }
    }

    private static void writeInitialRequest(EmbeddedChannel channel, FuzzedDataProvider data) {
        HttpRequest request = createRequest(data);
        if (request == null) {
            return;
        }
        addHeaders(request, data);
        channel.writeOutbound(request);
    }

    private static void writeFullRequest(EmbeddedChannel channel, FuzzedDataProvider data) {
        ByteBuf body = Unpooled.wrappedBuffer(data.consumeBytes(MAX_BODY_LENGTH));
        FullHttpRequest request;
        try {
            request = new DefaultFullHttpRequest(consumeVersion(data), consumeMethod(data), consumeUri(data), body);
        } catch (IllegalArgumentException e) {
            body.release();
            handleExpectedValidationException(e);
            return;
        } catch (RuntimeException e) {
            body.release();
            throw e;
        }
        addHeaders(request, data);
        channel.writeOutbound(request);
    }

    private static void writeChunkedRequest(EmbeddedChannel channel, FuzzedDataProvider data) {
        HttpRequest request = createRequest(data);
        if (request == null) {
            return;
        }
        addHeaders(request, data);
        channel.writeOutbound(request);
        channel.writeOutbound(new DefaultHttpContent(Unpooled.wrappedBuffer(data.consumeBytes(MAX_BODY_LENGTH))));
        channel.writeOutbound(LastHttpContent.EMPTY_LAST_CONTENT);
    }

    private static HttpRequest createRequest(FuzzedDataProvider data) {
        try {
            return new DefaultHttpRequest(consumeVersion(data), consumeMethod(data), consumeUri(data));
        } catch (IllegalArgumentException e) {
            handleExpectedValidationException(e);
            return null;
        }
    }

    private static HttpVersion consumeVersion(FuzzedDataProvider data) {
        return switch (data.consumeInt(0, 2)) {
            case 0 -> HttpVersion.HTTP_1_0;
            case 1 -> HttpVersion.HTTP_1_1;
            case 2 -> new HttpVersion(data.consumeString(16), data.consumeBoolean());
            default -> throw new IllegalStateException();
        };
    }

    private static HttpMethod consumeMethod(FuzzedDataProvider data) {
        return switch (data.consumeInt(0, 8)) {
            case 0 -> HttpMethod.GET;
            case 1 -> HttpMethod.POST;
            case 2 -> HttpMethod.PUT;
            case 3 -> HttpMethod.DELETE;
            case 4 -> HttpMethod.PATCH;
            case 5 -> HttpMethod.HEAD;
            case 6 -> HttpMethod.OPTIONS;
            case 7 -> HttpMethod.CONNECT;
            case 8 -> new HttpMethod(data.consumeString(32));
            default -> throw new IllegalStateException();
        };
    }

    private static String consumeUri(FuzzedDataProvider data) {
        return switch (data.consumeInt(0, 5)) {
            case 0 -> "";
            case 1 -> "/";
            case 2 -> "/" + data.consumeString(128);
            case 3 -> "/" + data.consumeString(96) + "?" + data.consumeString(96);
            case 4 -> "http://" + data.consumeString(64) + "/" + data.consumeString(128);
            case 5 -> data.consumeString(256);
            default -> throw new IllegalStateException();
        };
    }

    private static void addHeaders(HttpRequest request, FuzzedDataProvider data) {
        int headerCount = data.consumeInt(0, MAX_HEADER_COUNT);
        for (int i = 0; i < headerCount; i++) {
            try {
                request.headers().add(data.consumeString(MAX_HEADER_NAME_LENGTH), data.consumeString(MAX_HEADER_VALUE_LENGTH));
            } catch (IllegalArgumentException e) {
                handleExpectedValidationException(e);
            }
        }
    }

    private static void handleExpectedValidationException(IllegalArgumentException e) {
        if (e.getClass() != IllegalArgumentException.class && e.getMessage() == null) {
            throw e;
        }
    }

    public static void main(String[] args) {
        LocalJazzerRunner.create(HttpRequestEncoderFuzzer.class).fuzz();
    }
}
