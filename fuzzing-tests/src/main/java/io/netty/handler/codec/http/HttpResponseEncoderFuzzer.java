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
import io.micronaut.fuzzing.HttpDict;
import io.micronaut.fuzzing.runner.LocalJazzerRunner;
import io.netty.buffer.ByteBuf;
import io.netty.channel.ChannelFuture;
import io.netty.channel.ChannelHandlerContext;
import io.netty.channel.ChannelInboundHandlerAdapter;
import io.netty.channel.embedded.EmbeddedChannel;
import io.netty.handler.HandlerFuzzerBase;
import io.netty.handler.codec.EncoderException;
import io.netty.util.ReferenceCountUtil;

/**
 * Fuzzing support type.
 */
@FuzzTarget
@HttpDict
public class HttpResponseEncoderFuzzer extends HandlerFuzzerBase {
    private static final CharSequence[] HEADER_VALUES = {
        HttpHeaderValues.TEXT_PLAIN,
        HttpHeaderValues.APPLICATION_JSON,
        HttpHeaderValues.GZIP,
        HttpHeaderValues.NO_CACHE,
        HttpHeaderValues.UPGRADE,
    };

    @Override
    protected EmbeddedChannel setUp() {
        EmbeddedChannel channel = new EmbeddedChannel();
        channel.pipeline()
            .addLast(new HttpResponseEncoder())
            .addLast(new ChannelInboundHandlerAdapter() {
                @Override
                public void channelRead(ChannelHandlerContext ctx, Object msg) throws Exception {
                    if (msg instanceof ByteBuf input) {
                        try {
                            writeResponseObject(ctx, input);
                        } finally {
                            input.release();
                        }
                    } else {
                        ReferenceCountUtil.release(msg);
                    }
                }
            });
        return channel;
    }

    @Override
    protected void onException(Exception e) {
        if (isExpected(e)) {
            return;
        }
        super.onException(e);
    }

    private static boolean isExpected(Throwable cause) {
        return cause.getClass() == IllegalStateException.class ||
            cause instanceof EncoderException && cause.getCause() != null && (
                cause.getCause().getClass() == IllegalStateException.class ||
                    cause.getCause().getClass() == IllegalArgumentException.class
            );
    }

    private static void writeResponseObject(ChannelHandlerContext ctx, ByteBuf input) throws InterruptedException {
        Object message = createResponseObject(ctx, input);
        boolean handedOff = false;
        try {
            ChannelFuture future = ctx.writeAndFlush(message);
            handedOff = true;
            future.sync();
        } catch (RuntimeException | Error e) {
            if (!handedOff) {
                ReferenceCountUtil.release(message);
            }
            throw e;
        }
    }

    private static Object createResponseObject(ChannelHandlerContext ctx, ByteBuf input) {
        int selector = readByte(input);
        return switch (selector & 3) {
            case 0 -> createResponse(input);
            case 1 -> createFullResponse(ctx, input);
            case 2 -> new DefaultHttpContent(copyRemaining(ctx, input));
            default -> createLastContent(ctx, input);
        };
    }

    private static HttpResponse createResponse(ByteBuf input) {
        HttpResponse response = new DefaultHttpResponse(readVersion(input), readStatus(input));
        addHeaders(response.headers(), input);
        return response;
    }

    private static FullHttpResponse createFullResponse(ChannelHandlerContext ctx, ByteBuf input) {
        HttpVersion version = readVersion(input);
        HttpResponseStatus status = readStatus(input);
        HttpHeaders headers = new DefaultHttpHeaders();
        HttpHeaders trailingHeaders = new DefaultHttpHeaders();
        addHeaders(headers, input);
        addTrailingHeaders(trailingHeaders, input);
        DefaultFullHttpResponse response = new DefaultFullHttpResponse(version, status, copyRemaining(ctx, input));
        response.headers().add(headers);
        response.trailingHeaders().add(trailingHeaders);
        return response;
    }

    private static LastHttpContent createLastContent(ChannelHandlerContext ctx, ByteBuf input) {
        HttpHeaders trailingHeaders = new DefaultHttpHeaders();
        addTrailingHeaders(trailingHeaders, input);
        DefaultLastHttpContent content = new DefaultLastHttpContent(copyRemaining(ctx, input));
        content.trailingHeaders().add(trailingHeaders);
        return content;
    }

    private static void addHeaders(HttpHeaders headers, ByteBuf input) {
        int count = readByte(input) % 5;
        for (int i = 0; i < count; i++) {
            CharSequence name = readHeaderName(input);
            headers.add(name, readHeaderValue(name, input));
        }
    }

    private static void addTrailingHeaders(HttpHeaders headers, ByteBuf input) {
        int count = readByte(input) % 5;
        for (int i = 0; i < count; i++) {
            CharSequence name = readTrailingHeaderName(input);
            headers.add(name, readHeaderValue(name, input));
        }
    }

    private static CharSequence readHeaderName(ByteBuf input) {
        return switch (readByte(input) % 8) {
            case 0 -> HttpHeaderNames.CONTENT_LENGTH;
            case 1 -> HttpHeaderNames.TRANSFER_ENCODING;
            case 2 -> HttpHeaderNames.CONTENT_TYPE;
            case 3 -> HttpHeaderNames.CONNECTION;
            case 4 -> HttpHeaderNames.SEC_WEBSOCKET_VERSION;
            case 5 -> HttpHeaderNames.LOCATION;
            case 6 -> HttpHeaderNames.SERVER;
            default -> HttpHeaderNames.CACHE_CONTROL;
        };
    }

    private static CharSequence readTrailingHeaderName(ByteBuf input) {
        return switch (readByte(input) % 5) {
            case 0 -> HttpHeaderNames.CONTENT_TYPE;
            case 1 -> HttpHeaderNames.CACHE_CONTROL;
            case 2 -> HttpHeaderNames.SEC_WEBSOCKET_VERSION;
            case 3 -> HttpHeaderNames.LOCATION;
            default -> HttpHeaderNames.SERVER;
        };
    }

    private static Object readHeaderValue(CharSequence name, ByteBuf input) {
        if (HttpHeaderNames.CONTENT_LENGTH.contentEqualsIgnoreCase(name)) {
            return readByte(input);
        }
        if (HttpHeaderNames.TRANSFER_ENCODING.contentEqualsIgnoreCase(name)) {
            return HttpHeaderValues.CHUNKED;
        }
        if (HttpHeaderNames.CONNECTION.contentEqualsIgnoreCase(name)) {
            return (readByte(input) & 1) == 0 ? HttpHeaderValues.CLOSE : HttpHeaderValues.KEEP_ALIVE;
        }
        if (HttpHeaderNames.SEC_WEBSOCKET_VERSION.contentEqualsIgnoreCase(name)) {
            return 13;
        }
        return HEADER_VALUES[readByte(input) % HEADER_VALUES.length];
    }

    private static HttpVersion readVersion(ByteBuf input) {
        return (readByte(input) & 1) == 0 ? HttpVersion.HTTP_1_1 : HttpVersion.HTTP_1_0;
    }

    private static HttpResponseStatus readStatus(ByteBuf input) {
        return switch (readByte(input) % 8) {
            case 0 -> HttpResponseStatus.CONTINUE;
            case 1 -> HttpResponseStatus.SWITCHING_PROTOCOLS;
            case 2 -> HttpResponseStatus.OK;
            case 3 -> HttpResponseStatus.NO_CONTENT;
            case 4 -> HttpResponseStatus.RESET_CONTENT;
            case 5 -> HttpResponseStatus.NOT_MODIFIED;
            case 6 -> HttpResponseStatus.INTERNAL_SERVER_ERROR;
            default -> HttpResponseStatus.valueOf(100 + readByte(input) % 500);
        };
    }

    private static ByteBuf copyRemaining(ChannelHandlerContext ctx, ByteBuf input) {
        ByteBuf content = ctx.alloc().buffer(input.readableBytes());
        content.writeBytes(input, input.readableBytes());
        return content;
    }

    private static int readByte(ByteBuf input) {
        return input.isReadable() ? input.readUnsignedByte() : 0;
    }

    public static void fuzzerTestOneInput(FuzzedDataProvider fuzzedDataProvider) {
        new HttpResponseEncoderFuzzer().test(fuzzedDataProvider);
    }

    public static void main(String[] args) {
        LocalJazzerRunner.create(HttpResponseEncoderFuzzer.class).fuzz();
    }
}
