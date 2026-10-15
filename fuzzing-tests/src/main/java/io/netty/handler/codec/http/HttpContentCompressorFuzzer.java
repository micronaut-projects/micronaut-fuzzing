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
import io.micronaut.fuzzing.EmbeddedChannelFuzzerBase;
import io.micronaut.fuzzing.FlagAppender;
import io.micronaut.fuzzing.FuzzTarget;
import io.micronaut.fuzzing.runner.LocalJazzerRunner;
import io.micronaut.fuzzing.sanitizer.SanitizerTransformer;
import io.micronaut.fuzzing.util.ByteSplitter;
import io.netty.buffer.ByteBuf;
import io.netty.buffer.ByteBufUtil;
import io.netty.channel.embedded.EmbeddedChannel;
import io.netty.handler.codec.compression.CompressionOptions;
import io.netty.util.LeakPresenceDetector;
import io.netty.util.ReferenceCountUtil;
import io.netty.util.concurrent.FastThreadLocalThread;

import java.io.ByteArrayOutputStream;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

/**
 * Fuzzes {@link HttpContentCompressor} and checks that {@link HttpContentDecompressor} restores the original
 * response body from its output.
 * <p>
 * Unlike most Netty targets, this does not extend {@link EmbeddedChannelFuzzerBase}: the input is turned into
 * HTTP message objects rather than fed as bytes, and the round trip needs a second channel. As a consequence there
 * is no per-input CPU budget; compression time is linear in the body size, so Jazzer's timeout is sufficient.
 */
@FuzzTarget
@Dict({
    "gzip",
    "x-gzip",
    "deflate",
    "x-deflate",
    "br",
    "zstd",
    "snappy",
    "compress",
    "identity",
    "*",
    ";q=",
    ";q=0",
    ";q=1.0",
    ", ",
    EmbeddedChannelFuzzerBase.SEPARATOR
})
public final class HttpContentCompressorFuzzer {
    private static final ByteSplitter SPLITTER = ByteSplitter.create(EmbeddedChannelFuzzerBase.SEPARATOR);
    private static final int MAX_HEADER_VALUE_LENGTH = 128;
    private static final int MAX_ACCEPT_ENCODING_HEADERS = 2;
    private static final int MAX_CONTENT_SIZE_THRESHOLD = 64;
    private static final int MIN_STATUS = 100;
    private static final int MAX_STATUS = 599;

    private static final HttpMethod[] METHODS = {
        HttpMethod.GET,
        HttpMethod.POST,
        HttpMethod.HEAD,
        HttpMethod.CONNECT
    };

    static {
        // EmbeddedChannelFuzzerBase installs the sanitizer in its static initializer, which referencing its
        // SEPARATOR constant does not run
        SanitizerTransformer.installLocally();
    }

    private final int contentSizeThreshold;
    private final HttpMethod method;
    private final String[] acceptEncodings;
    private final HttpVersion responseVersion;
    private final int status;
    private final boolean fullResponse;
    private final boolean setContentLength;
    private final String contentEncoding;
    private final List<byte[]> chunks;
    private final byte[] body;

    private HttpContentCompressorFuzzer(FuzzedDataProvider data) {
        contentSizeThreshold = data.consumeInt(0, MAX_CONTENT_SIZE_THRESHOLD);
        method = data.pickValue(METHODS);
        acceptEncodings = new String[data.consumeInt(0, MAX_ACCEPT_ENCODING_HEADERS)];
        for (int i = 0; i < acceptEncodings.length; i++) {
            acceptEncodings[i] = headerValue(data.consumeString(MAX_HEADER_VALUE_LENGTH));
        }
        responseVersion = data.consumeBoolean() ? HttpVersion.HTTP_1_0 : HttpVersion.HTTP_1_1;
        status = data.consumeInt(MIN_STATUS, MAX_STATUS);
        fullResponse = data.consumeBoolean();
        setContentLength = data.consumeBoolean();
        contentEncoding = data.consumeBoolean() ? headerValue(data.consumeString(MAX_HEADER_VALUE_LENGTH)) : null;
        byte[] remaining = data.consumeRemainingAsBytes();
        chunks = new ArrayList<>();
        if (fullResponse) {
            chunks.add(remaining);
        } else {
            SPLITTER.splitIterator(remaining).forEachRemaining(chunks::add);
        }
        ByteArrayOutputStream joined = new ByteArrayOutputStream(remaining.length);
        chunks.forEach(joined::writeBytes);
        body = joined.toByteArray();
    }

    public static void fuzzerTestOneInput(FuzzedDataProvider fuzzedDataProvider) {
        HttpContentCompressorFuzzer fuzzer = new HttpContentCompressorFuzzer(fuzzedDataProvider);
        FastThreadLocalThread.runWithFastThreadLocal(fuzzer::test);
    }

    private void test() {
        EmbeddedChannel compressor = new EmbeddedChannel(new HttpContentCompressor(contentSizeThreshold, new CompressionOptions[0]));
        EmbeddedChannel decompressor = new EmbeddedChannel(new HttpContentDecompressor());
        try {
            compressor.writeInbound(request());
            compressor.releaseInbound();

            writeResponse(compressor);
            compressor.checkException();
            // If Content-Encoding was set by the application, the compressor passes the body through unchanged
            // and HttpContentDecompressor would try to decode it, so the round trip only holds without it.
            boolean roundTrip = contentEncoding == null;
            forwardAndCheckContentLength(compressor, roundTrip ? decompressor : null);
            if (roundTrip) {
                decompressor.finish();
                if (!Arrays.equals(body, readContent(decompressor))) {
                    throw new AssertionError("Decompressed content does not match the original body");
                }
            }
        } catch (Throwable t) {
            closeQuietly(compressor, t);
            closeQuietly(decompressor, t);
            throw t;
        }
        compressor.finishAndReleaseAll();
        decompressor.finishAndReleaseAll();
        LeakPresenceDetector.check();
        FlagAppender.checkTriggered();
    }

    private HttpRequest request() {
        DefaultHttpRequest request = new DefaultHttpRequest(HttpVersion.HTTP_1_1, method, "/");
        for (String acceptEncoding : acceptEncodings) {
            request.headers().add(HttpHeaderNames.ACCEPT_ENCODING, acceptEncoding);
        }
        return request;
    }

    /**
     * Turn a fuzzed string into a header value that passes Netty's default header validation, like a value that
     * {@link HttpObjectDecoder} produces: no control characters except HTAB, and no leading or trailing whitespace.
     */
    private static String headerValue(String value) {
        StringBuilder builder = new StringBuilder(value.length());
        for (int i = 0; i < value.length(); i++) {
            char c = value.charAt(i);
            if (c == '\t' || c >= 0x20 && c <= 0xff && c != 0x7f) {
                builder.append(c);
            }
        }
        return builder.toString().strip();
    }

    private void writeResponse(EmbeddedChannel channel) {
        HttpResponseStatus responseStatus = HttpResponseStatus.valueOf(status);
        HttpResponse response;
        if (fullResponse) {
            response = new DefaultFullHttpResponse(responseVersion, responseStatus, buffer(channel, body));
        } else {
            response = new DefaultHttpResponse(responseVersion, responseStatus);
        }
        if (setContentLength) {
            HttpUtil.setContentLength(response, body.length);
        }
        if (contentEncoding != null) {
            response.headers().set(HttpHeaderNames.CONTENT_ENCODING, contentEncoding);
        }
        channel.writeOutbound(response);
        if (!fullResponse) {
            for (int i = 0; i < chunks.size(); i++) {
                ByteBuf content = buffer(channel, chunks.get(i));
                channel.writeOutbound(i == chunks.size() - 1 ? new DefaultLastHttpContent(content) : new DefaultHttpContent(content));
            }
        }
    }

    private static ByteBuf buffer(EmbeddedChannel channel, byte[] bytes) {
        ByteBuf buffer = channel.alloc().buffer(bytes.length);
        buffer.writeBytes(bytes);
        return buffer;
    }

    /**
     * Pass the compressor output to the decompressor, and check that a Content-Length header in the compressor
     * output matches the length of the content that follows it.
     *
     * @param decompressor The decompressor, or {@code null} to only release the compressor output
     */
    private static void forwardAndCheckContentLength(EmbeddedChannel compressor, EmbeddedChannel decompressor) {
        long expectedLength = -1;
        long actualLength = 0;
        Object msg;
        while ((msg = compressor.readOutbound()) != null) {
            if (msg instanceof HttpResponse response) {
                expectedLength = HttpUtil.getContentLength(response, -1L);
            }
            if (msg instanceof HttpContent content) {
                actualLength += content.content().readableBytes();
            }
            boolean last = msg instanceof LastHttpContent;
            if (decompressor != null) {
                decompressor.writeInbound(msg);
            } else {
                ReferenceCountUtil.release(msg);
            }
            if (last && expectedLength != -1 && expectedLength != actualLength) {
                throw new AssertionError("Content-Length " + expectedLength + " does not match content length " + actualLength);
            }
        }
    }

    private static byte[] readContent(EmbeddedChannel decompressor) {
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        Object msg;
        while ((msg = decompressor.readInbound()) != null) {
            try {
                if (msg instanceof HttpContent content) {
                    out.writeBytes(ByteBufUtil.getBytes(content.content()));
                }
            } finally {
                ReferenceCountUtil.release(msg);
            }
        }
        return out.toByteArray();
    }

    private static void closeQuietly(EmbeddedChannel channel, Throwable original) {
        try {
            channel.finishAndReleaseAll();
        } catch (Throwable t) {
            original.addSuppressed(t);
        }
    }

    public static void main(String[] args) {
        LocalJazzerRunner.create(HttpContentCompressorFuzzer.class).fuzz();
    }
}
