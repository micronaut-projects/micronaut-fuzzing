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
import io.micronaut.fuzzing.HttpDict;
import io.micronaut.fuzzing.runner.LocalJazzerRunner;
import io.micronaut.fuzzing.util.ByteSplitter;
import io.netty.buffer.ByteBuf;
import io.netty.buffer.ByteBufUtil;
import io.netty.channel.embedded.EmbeddedChannel;
import io.netty.util.AsciiString;
import io.netty.util.LeakPresenceDetector;
import io.netty.util.ReferenceCountUtil;
import io.netty.util.concurrent.FastThreadLocalThread;

import java.io.ByteArrayOutputStream;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Iterator;
import java.util.List;
import java.util.Map;

/**
 * Fuzzes {@link HttpResponseEncoder} with valid sequences of response messages whose status line, headers, body
 * and trailers come from the input. If the input is unambiguous HTTP, the encoder output is decoded with
 * {@link HttpResponseDecoder} and compared with the original responses.
 */
@FuzzTarget
@HttpDict
@Dict({
    "Transfer-Encoding",
    "chunked",
    "Content-Length",
    "Trailer",
    "Sec-WebSocket-Version",
    "Upgrade",
    "websocket",
    "\r\n",
    ": ",
    EmbeddedChannelFuzzerBase.SEPARATOR
})
public final class HttpResponseEncoderFuzzer {
    private static final ByteSplitter SPLITTER = ByteSplitter.create(EmbeddedChannelFuzzerBase.SEPARATOR);
    private static final int MAX_RESPONSES = 4;
    private static final int MAX_HEADERS = 8;
    private static final int MAX_CHUNKS = 4;
    private static final int MAX_TRAILERS = 3;
    private static final int MIN_STATUS = 100;
    private static final int MAX_STATUS = 999;

    private static final DefaultHttpHeadersFactory VALIDATING_HEADERS = DefaultHttpHeadersFactory.headersFactory();
    private static final DefaultHttpHeadersFactory VALIDATING_TRAILERS = DefaultHttpHeadersFactory.trailersFactory();
    private static final DefaultHttpHeadersFactory NON_VALIDATING_HEADERS =
        DefaultHttpHeadersFactory.headersFactory().withValidation(false);
    private static final DefaultHttpHeadersFactory NON_VALIDATING_TRAILERS =
        DefaultHttpHeadersFactory.trailersFactory().withValidation(false);

    /**
     * Names of the headers that determine the message framing. The harness sets these itself, and
     * {@link HttpResponseEncoder} and {@link HttpObjectDecoder} rewrite them, so they are excluded from the comparison.
     * The validating trailers factory already rejects them in trailers.
     */
    private static final List<AsciiString> FRAMING_HEADERS = List.of(
        HttpHeaderNames.CONTENT_LENGTH,
        HttpHeaderNames.TRANSFER_ENCODING
    );

    private final boolean validateHeaders;
    private final List<Response> responses;
    private final boolean checkRoundTrip;

    private HttpResponseEncoderFuzzer(FuzzedDataProvider data) {
        validateHeaders = data.consumeBoolean();
        int responseCount = data.consumeInt(1, MAX_RESPONSES);
        List<ResponseShape> shapes = new ArrayList<>(responseCount);
        for (int i = 0; i < responseCount; i++) {
            shapes.add(ResponseShape.consume(data));
        }
        Iterator<byte[]> segments = SPLITTER.splitIterator(data.consumeRemainingAsBytes());
        responses = new ArrayList<>(responseCount);
        for (ResponseShape shape : shapes) {
            responses.add(shape.fill(segments, validateHeaders));
        }
        checkRoundTrip = isRoundTripWellDefined();
    }

    public static void fuzzerTestOneInput(FuzzedDataProvider fuzzedDataProvider) {
        HttpResponseEncoderFuzzer fuzzer = new HttpResponseEncoderFuzzer(fuzzedDataProvider);
        FastThreadLocalThread.runWithFastThreadLocal(fuzzer::test);
    }

    /**
     * Whether {@link HttpResponseDecoder} must restore the responses exactly from the encoder output.
     */
    private boolean isRoundTripWellDefined() {
        if (!validateHeaders) {
            // header names and values may contain CR, LF, ':' etc., the output is not unambiguous
            return false;
        }
        for (int i = 0; i < responses.size(); i++) {
            Response response = responses.get(i);
            if (response.status.code() == HttpResponseStatus.SWITCHING_PROTOCOLS.code()) {
                // the decoder stops parsing HTTP after a protocol switch, and the encoder and decoder disagree on
                // whether a 101 response has a body
                return false;
            }
            if (!isUnambiguousReasonPhrase(response.status.reasonPhrase())) {
                return false;
            }
            if (response.shape.framing() == Framing.CLOSE_DELIMITED && i != responses.size() - 1) {
                // the decoder reads all following responses as the body of this one
                return false;
            }
            if (response.shape.framing() == Framing.CHUNKED && !response.shape.version().equals(HttpVersion.HTTP_1_1)) {
                // the decoder rejects Transfer-Encoding for HTTP/1.0
                return false;
            }
            if (hasFramingHeader(response.headers)) {
                return false;
            }
        }
        return true;
    }

    /**
     * Whether the decoder reads the reason phrase back unchanged: it trims surrounding whitespace, and the
     * {@link HttpResponseStatus} constructor encodes the phrase as US-ASCII.
     */
    private static boolean isUnambiguousReasonPhrase(String reasonPhrase) {
        for (int i = 0; i < reasonPhrase.length(); i++) {
            char c = reasonPhrase.charAt(i);
            boolean whitespace = c == ' ' || c == '\t';
            if (whitespace && (i == 0 || i == reasonPhrase.length() - 1) || !whitespace && (c < 0x21 || c > 0x7e)) {
                return false;
            }
        }
        return true;
    }

    private static boolean hasFramingHeader(List<Map.Entry<String, String>> headers) {
        for (Map.Entry<String, String> header : headers) {
            if (isFramingHeader(header.getKey())) {
                return true;
            }
        }
        return false;
    }

    private void test() {
        EmbeddedChannel encoder = new EmbeddedChannel(new HttpResponseEncoder());
        EmbeddedChannel decoder = new EmbeddedChannel(new HttpResponseDecoder(new HttpDecoderConfig()
            .setMaxInitialLineLength(Integer.MAX_VALUE)
            .setMaxHeaderSize(Integer.MAX_VALUE)));
        try {
            for (Response response : responses) {
                response.write(encoder);
            }
            encoder.checkException();
            Object msg;
            while ((msg = encoder.readOutbound()) != null) {
                if (checkRoundTrip) {
                    decoder.writeInbound(msg);
                } else {
                    ReferenceCountUtil.release(msg);
                }
            }
            if (checkRoundTrip) {
                decoder.finish();
                checkDecoded(decoder);
            }
        } catch (Throwable t) {
            closeQuietly(encoder, t);
            closeQuietly(decoder, t);
            throw t;
        }
        encoder.finishAndReleaseAll();
        decoder.finishAndReleaseAll();
        LeakPresenceDetector.check();
        FlagAppender.checkTriggered();
    }

    private void checkDecoded(EmbeddedChannel decoder) {
        Iterator<Response> expected = responses.iterator();
        Response current = null;
        ByteArrayOutputStream body = null;
        Object msg;
        while ((msg = decoder.readInbound()) != null) {
            try {
                if (!((HttpObject) msg).decoderResult().isSuccess()) {
                    throw new AssertionError("Failed to decode encoder output", ((HttpObject) msg).decoderResult().cause());
                }
                if (msg instanceof HttpResponse response) {
                    if (current != null || !expected.hasNext()) {
                        throw new AssertionError("Unexpected response " + response);
                    }
                    current = expected.next();
                    current.checkHead(response);
                    body = new ByteArrayOutputStream();
                }
                if (msg instanceof HttpContent content) {
                    if (current == null) {
                        throw new AssertionError("Unexpected content " + content);
                    }
                    body.writeBytes(ByteBufUtil.getBytes(content.content()));
                }
                if (msg instanceof LastHttpContent last) {
                    current.checkBody(body.toByteArray(), last.trailingHeaders());
                    current = null;
                }
            } finally {
                ReferenceCountUtil.release(msg);
            }
        }
        if (current != null || expected.hasNext()) {
            throw new AssertionError("Missing response in decoder output");
        }
    }

    private static void closeQuietly(EmbeddedChannel channel, Throwable original) {
        try {
            channel.finishAndReleaseAll();
        } catch (Throwable t) {
            original.addSuppressed(t);
        }
    }

    private static ByteBuf buffer(EmbeddedChannel channel, byte[] bytes) {
        ByteBuf buffer = channel.alloc().buffer(bytes.length);
        buffer.writeBytes(bytes);
        return buffer;
    }

    /**
     * Decode raw input bytes one char per byte, so that the encoder writes them back unchanged.
     */
    private static String string(byte[] bytes) {
        return new String(bytes, StandardCharsets.ISO_8859_1);
    }

    private static byte[] next(Iterator<byte[]> segments) {
        return segments.hasNext() ? segments.next() : new byte[0];
    }

    private static List<Map.Entry<String, String>> headers(Iterator<byte[]> segments, int count, DefaultHttpHeadersFactory factory) {
        List<Map.Entry<String, String>> headers = new ArrayList<>(count);
        for (int i = 0; i < count; i++) {
            String name = string(next(segments));
            String value = string(next(segments));
            if (isValid(factory, name, value)) {
                headers.add(Map.entry(name, value));
            }
        }
        return headers;
    }

    /**
     * Skip the headers that the headers factory rejects, so that building the messages never fails.
     */
    private static boolean isValid(DefaultHttpHeadersFactory factory, String name, String value) {
        try {
            factory.getNameValidator().validateName(name);
            factory.getValueValidator().validate(value);
            return true;
        } catch (IllegalArgumentException e) {
            return false;
        }
    }

    private static void addHeaders(HttpHeaders target, List<Map.Entry<String, String>> headers) {
        for (Map.Entry<String, String> header : headers) {
            target.add(header.getKey(), header.getValue());
        }
    }

    /**
     * Check that the decoded headers equal the original headers, except for the framing headers and the trailing
     * whitespace of values, which the decoder strips.
     */
    private static void checkHeaders(String what, List<Map.Entry<String, String>> expected, HttpHeaders actual) {
        List<Map.Entry<String, String>> actualList = new ArrayList<>();
        for (Map.Entry<CharSequence, CharSequence> header : iterable(actual)) {
            if (!isFramingHeader(header.getKey())) {
                actualList.add(Map.entry(header.getKey().toString(), header.getValue().toString()));
            }
        }
        List<Map.Entry<String, String>> expectedList = new ArrayList<>(expected.size());
        for (Map.Entry<String, String> header : expected) {
            expectedList.add(Map.entry(header.getKey(), stripTrailingWhitespace(header.getValue())));
        }
        if (!expectedList.equals(actualList)) {
            throw new AssertionError(what + " mismatch: expected " + expectedList + ", got " + actualList);
        }
    }

    private static Iterable<Map.Entry<CharSequence, CharSequence>> iterable(HttpHeaders headers) {
        return headers::iteratorCharSequence;
    }

    private static boolean isFramingHeader(CharSequence name) {
        for (AsciiString framingHeader : FRAMING_HEADERS) {
            if (framingHeader.contentEqualsIgnoreCase(name)) {
                return true;
            }
        }
        return false;
    }

    private static String stripTrailingWhitespace(String value) {
        int end = value.length();
        while (end > 0 && (value.charAt(end - 1) == ' ' || value.charAt(end - 1) == '\t')) {
            end--;
        }
        return value.substring(0, end);
    }

    public static void main(String[] args) {
        LocalJazzerRunner.create(HttpResponseEncoderFuzzer.class).fuzz();
    }

    private enum Framing {
        CONTENT_LENGTH,
        CHUNKED,
        CLOSE_DELIMITED
    }

    private enum ChunkType {
        HTTP_CONTENT,
        BYTE_BUF
    }

    // The structure of one response, consumed from the FuzzedDataProvider before the raw segments.
    private record ResponseShape(
        HttpVersion version,
        int code,
        boolean customReasonPhrase,
        Framing framing,
        int headerCount,
        boolean full,
        ChunkType[] chunkTypes,
        boolean emptyLastContent,
        int trailerCount
    ) {
        static ResponseShape consume(FuzzedDataProvider data) {
            HttpVersion version = data.consumeBoolean() ? HttpVersion.HTTP_1_1 : HttpVersion.HTTP_1_0;
            int code = data.consumeInt(MIN_STATUS, MAX_STATUS);
            boolean customReasonPhrase = data.consumeBoolean();
            Framing framing = Framing.values()[data.consumeInt(0, Framing.values().length - 1)];
            int headerCount = data.consumeInt(0, MAX_HEADERS);
            boolean full = data.consumeBoolean();
            ChunkType[] chunkTypes = new ChunkType[full ? 0 : data.consumeInt(0, MAX_CHUNKS)];
            for (int i = 0; i < chunkTypes.length; i++) {
                chunkTypes[i] = data.consumeBoolean() ? ChunkType.HTTP_CONTENT : ChunkType.BYTE_BUF;
            }
            boolean emptyLastContent = !full && data.consumeBoolean();
            int trailerCount = emptyLastContent ? 0 : data.consumeInt(0, MAX_TRAILERS);
            return new ResponseShape(version, code, customReasonPhrase, framing, headerCount, full, chunkTypes,
                emptyLastContent, trailerCount);
        }

        Response fill(Iterator<byte[]> segments, boolean validate) {
            HttpResponseStatus status = HttpResponseStatus.valueOf(code);
            if (customReasonPhrase) {
                String reasonPhrase = string(next(segments));
                // the constructor rejects CR and LF
                if (reasonPhrase.indexOf('\r') == -1 && reasonPhrase.indexOf('\n') == -1) {
                    status = new HttpResponseStatus(code, reasonPhrase);
                }
            }
            List<Map.Entry<String, String>> headers = headers(segments, headerCount,
                validate ? VALIDATING_HEADERS : NON_VALIDATING_HEADERS);
            List<byte[]> chunks = new ArrayList<>();
            int chunkCount = full ? 1 : chunkTypes.length + (emptyLastContent ? 0 : 1);
            for (int i = 0; i < chunkCount; i++) {
                chunks.add(next(segments));
            }
            List<Map.Entry<String, String>> trailers = headers(segments, trailerCount,
                validate ? VALIDATING_TRAILERS : NON_VALIDATING_TRAILERS);
            return new Response(this, status, headers, chunks, trailers, validate);
        }
    }

    private record Response(
        ResponseShape shape,
        HttpResponseStatus status,
        List<Map.Entry<String, String>> headers,
        List<byte[]> chunks,
        List<Map.Entry<String, String>> trailers,
        boolean validate
    ) {
        void write(EmbeddedChannel channel) {
            HttpHeadersFactory headersFactory = validate ? VALIDATING_HEADERS : NON_VALIDATING_HEADERS;
            HttpHeadersFactory trailersFactory = validate ? VALIDATING_TRAILERS : NON_VALIDATING_TRAILERS;
            HttpVersion version = shape.version();
            HttpResponse response;
            if (shape.full()) {
                FullHttpResponse full = new DefaultFullHttpResponse(version, status, buffer(channel, chunks.get(0)),
                    headersFactory, trailersFactory);
                addHeaders(full.trailingHeaders(), trailers);
                response = full;
            } else {
                response = new DefaultHttpResponse(version, status, headersFactory);
            }
            addHeaders(response.headers(), headers);
            switch (shape.framing()) {
                case CONTENT_LENGTH -> response.headers().add(HttpHeaderNames.CONTENT_LENGTH, bodyLength());
                case CHUNKED -> response.headers().add(HttpHeaderNames.TRANSFER_ENCODING, HttpHeaderValues.CHUNKED);
                default -> {
                }
            }
            channel.writeOutbound(response);
            if (shape.full()) {
                return;
            }
            ChunkType[] chunkTypes = shape.chunkTypes();
            for (int i = 0; i < chunkTypes.length; i++) {
                ByteBuf content = buffer(channel, chunks.get(i));
                channel.writeOutbound(chunkTypes[i] == ChunkType.HTTP_CONTENT ? new DefaultHttpContent(content) : content);
            }
            if (shape.emptyLastContent()) {
                channel.writeOutbound(LastHttpContent.EMPTY_LAST_CONTENT);
            } else {
                LastHttpContent last = new DefaultLastHttpContent(buffer(channel, chunks.get(chunkTypes.length)), trailersFactory);
                addHeaders(last.trailingHeaders(), trailers);
                channel.writeOutbound(last);
            }
        }

        private int bodyLength() {
            int length = 0;
            for (byte[] chunk : chunks) {
                length += chunk.length;
            }
            return length;
        }

        /**
         * Whether the encoder omits the body. The status codes match
         * {@link HttpResponseEncoder#isContentAlwaysEmpty(HttpResponse)}, except for 101, which is excluded from
         * the round trip check.
         */
        private boolean hasNoBody() {
            int code = status.code();
            return status.codeClass() == HttpStatusClass.INFORMATIONAL || code == 204 || code == 205 || code == 304;
        }

        void checkHead(HttpResponse decoded) {
            if (!shape.version().equals(decoded.protocolVersion())) {
                throw new AssertionError("Version mismatch: expected " + shape.version() + ", got " + decoded.protocolVersion());
            }
            if (status.code() != decoded.status().code() || !status.reasonPhrase().equals(decoded.status().reasonPhrase())) {
                throw new AssertionError("Status mismatch: expected " + status + ", got " + decoded.status());
            }
            checkHeaders("Header", headers, decoded.headers());
        }

        void checkBody(byte[] decodedBody, HttpHeaders decodedTrailers) {
            byte[] expectedBody;
            if (hasNoBody()) {
                expectedBody = new byte[0];
            } else {
                ByteArrayOutputStream joined = new ByteArrayOutputStream();
                chunks.forEach(joined::writeBytes);
                expectedBody = joined.toByteArray();
            }
            if (!Arrays.equals(expectedBody, decodedBody)) {
                throw new AssertionError("Body mismatch for " + status + ": expected " + expectedBody.length
                    + " bytes, got " + decodedBody.length);
            }
            // the encoder only writes trailers for chunked framing
            boolean trailersSent = shape.framing() == Framing.CHUNKED && !hasNoBody();
            checkHeaders("Trailer", trailersSent ? trailers : List.of(), decodedTrailers);
        }
    }
}
