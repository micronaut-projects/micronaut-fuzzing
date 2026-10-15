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
import io.micronaut.fuzzing.sanitizer.SanitizerTransformer;
import io.netty.buffer.ByteBuf;
import io.netty.buffer.ByteBufAllocator;
import io.netty.buffer.ByteBufUtil;
import io.netty.buffer.Unpooled;
import io.netty.channel.embedded.EmbeddedChannel;
import io.netty.handler.codec.DecoderResultProvider;
import io.netty.util.AsciiString;
import io.netty.util.LeakPresenceDetector;
import io.netty.util.ReferenceCountUtil;
import io.netty.util.concurrent.FastThreadLocalThread;

import java.io.ByteArrayOutputStream;
import java.nio.charset.StandardCharsets;
import java.util.AbstractMap;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Iterator;
import java.util.List;
import java.util.Map;
import java.util.Objects;

/**
 * Fuzzes {@link HttpRequestEncoder} with valid message sequences (several requests per channel, each either a
 * {@link FullHttpRequest} or an {@link HttpRequest} followed by content and a {@link LastHttpContent}), built from
 * raw method, URI, header and body input.
 * <p>
 * Oracles:
 * <ul>
 *     <li>Method, URI and header validation must accept exactly the values that can be encoded safely. A value that
 *     slips past validation can inject data into the encoded request.</li>
 *     <li>The output of each request that can round trip is fed to one long-lived {@link HttpRequestDecoder}, which
 *     must decode exactly the same method, URI, version, headers, body and trailers, and nothing else. Requests that
 *     cannot round trip (e.g. a header with CRLF when validation is off, or a URI with a tab) are still encoded, but
 *     their output is not decoded, so they don't affect the check of the following requests.</li>
 * </ul>
 * <p>
 * Unlike {@code EmbeddedChannelFuzzerBase}, this target has no CPU budget: the number and size of all requests,
 * headers and body parts is capped, and the encoder and decoder are linear in their input, so the work per input is
 * bounded by a small constant. Jazzer's own timeout still catches hangs.
 */
@FuzzTarget
@HttpDict
@Dict({
    "HTTP/1.0", "HTTP/1.1", "HTTP/2.0", "http/1.1", "HTTP/1.10", "ICAP/1.0",
    "://", "http://", "https://", "http://example.com", "http://example.com?a=b", "?", "#", "/", "*",
    "content-length", "Content-Length", "transfer-encoding", "Transfer-Encoding", "chunked", "trailer", "te",
    "sec-websocket-key1", "sec-websocket-key2",
    "\t", " ", "\r", "\n", "\r\n", ":", "ÿ", "Ā", "Ċ", "\ud800"
})
public final class HttpRequestEncoderFuzzer {
    private static final int MAX_REQUESTS = 4;
    private static final int MAX_HEADERS = 8;
    private static final int MAX_TRAILERS = 4;
    private static final int MAX_CHUNKS = 4;
    private static final int MAX_VERSION_LENGTH = 16;
    private static final int MAX_METHOD_LENGTH = 32;
    private static final int MAX_URI_LENGTH = 256;
    private static final int MAX_HEADER_NAME_LENGTH = 64;
    private static final int MAX_HEADER_VALUE_LENGTH = 256;
    private static final int MAX_BODY_LENGTH = 512;
    private static final int MAX_DECODER_LINE_LENGTH = 1 << 20;

    private static final int FRAMING_CONTENT_LENGTH = 0;
    private static final int FRAMING_CHUNKED = 1;
    private static final int FRAMING_NONE = 2;

    private static final int CHUNK_HTTP_CONTENT = 0;
    private static final int CHUNK_BYTE_BUF = 1;
    private static final int CHUNK_EMPTY_BUFFER = 2;

    private static final String TCHAR_SYMBOLS = "!#$%&'*+-.^_`|~";

    static {
        // not done by EmbeddedChannelFuzzerBase, since this target does not extend it
        SanitizerTransformer.installLocally();
    }

    private final FuzzedDataProvider data;
    private final EmbeddedChannel encoderChannel;
    private final EmbeddedChannel decoderChannel;
    private final ByteBufAllocator alloc;
    private int roundTrips;

    private HttpRequestEncoderFuzzer(FuzzedDataProvider data) {
        this.data = data;
        // encoders and decoders are not @Sharable and keep state, so create fresh ones for each input
        this.encoderChannel = new EmbeddedChannel(new HttpRequestEncoder());
        this.decoderChannel = new EmbeddedChannel(new CheckedDecoder());
        this.alloc = encoderChannel.alloc();
    }

    public static void fuzzerTestOneInput(FuzzedDataProvider data) {
        fuzz(data);
    }

    /**
     * Run one input.
     *
     * @param data The input
     * @return The number of requests that were checked by decoding them again
     */
    static int fuzz(FuzzedDataProvider data) {
        int[] roundTrips = new int[1];
        FastThreadLocalThread.runWithFastThreadLocal(() -> {
            roundTrips[0] = new HttpRequestEncoderFuzzer(data).run();
            LeakPresenceDetector.check();
            FlagAppender.checkTriggered();
        });
        return roundTrips[0];
    }

    private int run() {
        try {
            int requestCount = data.consumeInt(1, MAX_REQUESTS);
            for (int i = 0; i < requestCount; i++) {
                writeRequest();
            }
            return roundTrips;
        } finally {
            encoderChannel.finishAndReleaseAll();
            decoderChannel.finishAndReleaseAll();
        }
    }

    private void writeRequest() {
        int noise = data.consumeInt(0, 2);
        HttpVersion version = consumeVersion();
        String methodName = data.consumeString(MAX_METHOD_LENGTH);
        String uri = data.consumeString(MAX_URI_LENGTH);
        boolean validate = data.consumeBoolean();
        boolean full = data.consumeBoolean();
        int framing = data.consumeInt(FRAMING_CONTENT_LENGTH, FRAMING_NONE);
        int headerCount = data.consumeInt(0, MAX_HEADERS);
        int framingPosition = data.consumeInt(0, headerCount);
        List<CharSequence[]> headers = consumeHeaders(headerCount);

        byte[] fullBody = null;
        List<byte[]> chunks = new ArrayList<>();
        int[] chunkKinds = null;
        byte[] lastChunk = null;
        if (full) {
            fullBody = data.consumeBytes(MAX_BODY_LENGTH);
        } else {
            chunkKinds = new int[data.consumeInt(0, MAX_CHUNKS)];
            for (int i = 0; i < chunkKinds.length; i++) {
                chunkKinds[i] = data.consumeInt(CHUNK_HTTP_CONTENT, CHUNK_EMPTY_BUFFER);
                chunks.add(chunkKinds[i] == CHUNK_EMPTY_BUFFER ? new byte[0] : data.consumeBytes(MAX_BODY_LENGTH));
            }
            if (data.consumeBoolean()) {
                lastChunk = data.consumeBytes(MAX_BODY_LENGTH);
            }
        }
        List<CharSequence[]> trailers = full || lastChunk != null
            ? consumeHeaders(data.consumeInt(0, MAX_TRAILERS))
            : List.of();

        if (version == null) {
            return;
        }
        HttpMethod method;
        try {
            method = HttpMethod.valueOf(methodName);
        } catch (IllegalArgumentException e) {
            expectRejected(e, isToken(methodName), "method", methodName);
            return;
        }
        if (!isToken(methodName)) {
            throw new AssertionError("Invalid method accepted: " + escape(methodName));
        }

        ByteArrayOutputStream body = new ByteArrayOutputStream();
        if (full) {
            body.writeBytes(fullBody);
        } else {
            chunks.forEach(body::writeBytes);
            if (lastChunk != null) {
                body.writeBytes(lastChunk);
            }
        }

        DefaultHttpHeadersFactory headersFactory = DefaultHttpHeadersFactory.headersFactory().withValidation(validate);
        DefaultHttpHeadersFactory trailersFactory = validate
            // trailersFactory().withValidation(true) drops the check for prohibited trailers, so avoid it
            ? DefaultHttpHeadersFactory.trailersFactory()
            : DefaultHttpHeadersFactory.trailersFactory().withValidation(false);
        HttpRequest request;
        try {
            if (full) {
                ByteBuf content = alloc.buffer(fullBody.length).writeBytes(fullBody);
                try {
                    request = new DefaultFullHttpRequest(version, method, uri, content, headersFactory, trailersFactory);
                } catch (IllegalArgumentException e) {
                    content.release();
                    throw e;
                }
            } else {
                request = new DefaultHttpRequest(version, method, uri, headersFactory);
            }
        } catch (IllegalArgumentException e) {
            expectRejected(e, isSafeRequestTarget(uri), "URI", uri);
            return;
        }
        if (!isSafeRequestTarget(uri)) {
            throw new AssertionError("Invalid URI accepted: " + escape(uri));
        }

        for (int i = 0; i <= headers.size(); i++) {
            if (i == framingPosition) {
                if (framing == FRAMING_CONTENT_LENGTH) {
                    request.headers().add(HttpHeaderNames.CONTENT_LENGTH, String.valueOf(body.size()));
                } else if (framing == FRAMING_CHUNKED) {
                    request.headers().add(HttpHeaderNames.TRANSFER_ENCODING, HttpHeaderValues.CHUNKED);
                }
            }
            if (i < headers.size()) {
                CharSequence[] header = headers.get(i);
                addHeader(request.headers(), header[0], header[1], validate, false);
            }
        }

        LastHttpContent last = null;
        HttpHeaders trailingHeaders;
        if (full) {
            trailingHeaders = ((FullHttpRequest) request).trailingHeaders();
        } else if (lastChunk != null) {
            last = new DefaultLastHttpContent(alloc.buffer(lastChunk.length).writeBytes(lastChunk), trailersFactory);
            trailingHeaders = last.trailingHeaders();
        } else {
            last = LastHttpContent.EMPTY_LAST_CONTENT;
            trailingHeaders = last.trailingHeaders();
        }
        for (CharSequence[] trailer : trailers) {
            addHeader(trailingHeaders, trailer[0], trailer[1], validate, true);
        }

        // compute this before writing, the encoder releases the messages
        ExpectedRequest expected = expectedRequest(request, version, uri, body.toByteArray(), trailingHeaders);

        switch (noise) {
            case 1 -> encoderChannel.writeOutbound(Unpooled.EMPTY_BUFFER);
            case 2 -> encoderChannel.writeOutbound(alloc.buffer(0));
            default -> {
            }
        }
        encoderChannel.writeOutbound(request);
        if (!full) {
            for (int i = 0; i < chunks.size(); i++) {
                byte[] chunk = chunks.get(i);
                switch (chunkKinds[i]) {
                    case CHUNK_HTTP_CONTENT ->
                        encoderChannel.writeOutbound(new DefaultHttpContent(alloc.buffer(chunk.length).writeBytes(chunk)));
                    case CHUNK_BYTE_BUF -> encoderChannel.writeOutbound(alloc.buffer(chunk.length).writeBytes(chunk));
                    default -> encoderChannel.writeOutbound(Unpooled.EMPTY_BUFFER);
                }
            }
            encoderChannel.writeOutbound(last);
        }

        if (expected == null) {
            // this request can't round trip, so don't let it desynchronize the decoder
            encoderChannel.releaseOutbound();
        } else {
            verifyRoundTrip(expected);
            roundTrips++;
        }
    }

    private HttpVersion consumeVersion() {
        return switch (data.consumeInt(0, 2)) {
            case 0 -> HttpVersion.HTTP_1_0;
            case 1 -> HttpVersion.HTTP_1_1;
            default -> {
                String text = data.consumeString(MAX_VERSION_LENGTH);
                try {
                    yield HttpVersion.valueOf(text);
                } catch (IllegalArgumentException e) {
                    if (e.getClass() != IllegalArgumentException.class) {
                        throw e;
                    }
                    yield null;
                }
            }
        };
    }

    private List<CharSequence[]> consumeHeaders(int count) {
        List<CharSequence[]> headers = new ArrayList<>(count);
        for (int i = 0; i < count; i++) {
            CharSequence name = consumeCharSequence(MAX_HEADER_NAME_LENGTH);
            CharSequence value = consumeCharSequence(MAX_HEADER_VALUE_LENGTH);
            headers.add(new CharSequence[]{name, value});
        }
        return headers;
    }

    private CharSequence consumeCharSequence(int maxLength) {
        String s = data.consumeString(maxLength);
        // AsciiString takes a different path through validation and HttpHeadersEncoder
        return data.consumeBoolean() ? new AsciiString(s) : s;
    }

    /**
     * Add a header, and check that validation accepts it exactly when it is valid.
     */
    private static void addHeader(HttpHeaders headers, CharSequence name, CharSequence value, boolean validate,
                                  boolean trailer) {
        boolean valid = isValidHeader(name, value) && !(trailer && isProhibitedTrailer(name));
        try {
            headers.add(name, value);
        } catch (IllegalArgumentException e) {
            if (e.getClass() != IllegalArgumentException.class || !validate || valid) {
                throw e;
            }
            return;
        }
        if (validate && !valid) {
            throw new AssertionError("Invalid " + (trailer ? "trailer" : "header") + " accepted: "
                + escape(name) + ": " + escape(value));
        }
    }

    private static void expectRejected(IllegalArgumentException e, boolean valid, String what, String value) {
        if (e.getClass() != IllegalArgumentException.class) {
            throw e;
        }
        if (valid) {
            throw new AssertionError("Valid " + what + " rejected: " + escape(value), e);
        }
    }

    /**
     * Determine what the decoder should see for this request.
     *
     * @return The expected decoded request, or {@code null} if this request can't round trip
     */
    private static ExpectedRequest expectedRequest(HttpRequest request, HttpVersion version, String uri, byte[] body,
                                                   HttpHeaders trailingHeaders) {
        // the decoder only accepts this version format
        if (!isStrictVersion(version.text())
            // the decoder splits the request line on whitespace other than SP, and rejects other control chars
            // between the tokens
            || !hasNoControlOrSpace(uri.getBytes(StandardCharsets.UTF_8))
            // with validation off, the header may be anything, including CRLF
            || !allValid(request.headers())) {
            return null;
        }
        Boolean chunked = chunked(request, body.length);
        if (chunked == null) {
            return null;
        }
        List<Map.Entry<String, String>> trailers = List.of();
        if (chunked) {
            if (!allValid(trailingHeaders)) {
                return null;
            }
            // the decoder drops prohibited trailers. They are only possible when validation is off
            trailers = expectedHeaders(trailingHeaders, true);
        }
        return new ExpectedRequest(
            request.method().name(),
            new String(expectedUri(uri).getBytes(StandardCharsets.UTF_8), StandardCharsets.ISO_8859_1),
            version.text(),
            expectedHeaders(request.headers(), false),
            body,
            // trailers only exist in chunked encoding, the encoder drops them otherwise
            trailers
        );
    }

    /**
     * Determine the framing of the request from its headers, regardless of whether this harness or the input added
     * them.
     *
     * @return Whether the request is chunked, or {@code null} if the decoder would frame it differently than the
     * encoder
     */
    private static Boolean chunked(HttpRequest request, int bodyLength) {
        HttpHeaders headers = request.headers();
        List<String> transferEncoding = headers.getAll(HttpHeaderNames.TRANSFER_ENCODING);
        List<String> contentLength = headers.getAll(HttpHeaderNames.CONTENT_LENGTH);
        if (!transferEncoding.isEmpty()) {
            // the decoder only accepts transfer-encoding with HTTP/1.1
            boolean simpleChunked = transferEncoding.size() == 1 && contentLength.isEmpty()
                && HttpHeaderValues.CHUNKED.contentEqualsIgnoreCase(transferEncoding.get(0))
                && request.protocolVersion().text().equals(HttpVersion.HTTP_1_1.text());
            return simpleChunked ? Boolean.TRUE : null;
        }
        if (!contentLength.isEmpty()) {
            boolean exactLength = contentLength.size() == 1 && contentLength.get(0).equals(String.valueOf(bodyLength));
            return exactLength ? Boolean.FALSE : null;
        }
        // without framing headers, a request has no body, except for a hixie-76 websocket handshake
        boolean websocket = HttpMethod.GET.equals(request.method())
            && headers.contains(HttpHeaderNames.SEC_WEBSOCKET_KEY1)
            && headers.contains(HttpHeaderNames.SEC_WEBSOCKET_KEY2);
        return bodyLength == 0 && !websocket ? Boolean.FALSE : null;
    }

    private void verifyRoundTrip(ExpectedRequest exp) {
        for (Object encoded; (encoded = encoderChannel.readOutbound()) != null; ) {
            decoderChannel.writeInbound(encoded);
        }
        decoderChannel.checkException();

        Object first = decoderChannel.readInbound();
        try {
            if (!(first instanceof HttpRequest request) || first instanceof HttpContent) {
                throw new AssertionError("Expected an HttpRequest, got " + first);
            }
            checkDecoded(request);
            checkEquals("method", exp.method(), request.method().name());
            checkEquals("URI", exp.uri(), request.uri());
            checkEquals("version", exp.version(), request.protocolVersion().text());
            checkEquals("headers", exp.headers(), decodedHeaders(request.headers()));
        } finally {
            ReferenceCountUtil.release(first);
        }
        ByteArrayOutputStream body = new ByteArrayOutputStream();
        while (true) {
            Object next = decoderChannel.readInbound();
            try {
                if (!(next instanceof HttpContent content) || next instanceof HttpRequest) {
                    throw new AssertionError("Expected HttpContent, got " + next);
                }
                checkDecoded(content);
                body.writeBytes(ByteBufUtil.getBytes(content.content()));
                if (content instanceof LastHttpContent lastContent) {
                    checkEquals("trailers", exp.trailers(), decodedHeaders(lastContent.trailingHeaders()));
                    break;
                }
            } finally {
                ReferenceCountUtil.release(next);
            }
        }
        if (!Arrays.equals(exp.body(), body.toByteArray())) {
            throw new AssertionError("Body mismatch: expected " + Arrays.toString(exp.body())
                + ", decoded " + Arrays.toString(body.toByteArray()));
        }
        Object extra = decoderChannel.readInbound();
        if (extra != null) {
            ReferenceCountUtil.release(extra);
            throw new AssertionError("Unexpected extra decoded message: " + extra);
        }
        int leftover = decoderChannel.pipeline().get(CheckedDecoder.class).leftover();
        if (leftover != 0) {
            throw new AssertionError("Encoder wrote " + leftover + " bytes after the end of the request");
        }
    }

    private static void checkDecoded(DecoderResultProvider message) {
        if (!message.decoderResult().isSuccess()) {
            throw new AssertionError("Decoder rejected the encoder output", message.decoderResult().cause());
        }
    }

    private static void checkEquals(String what, Object expected, Object actual) {
        if (!Objects.equals(expected, actual)) {
            throw new AssertionError(what + " mismatch: expected " + escape(String.valueOf(expected))
                + ", decoded " + escape(String.valueOf(actual)));
        }
    }

    /**
     * The URI the encoder is expected to write: it adds the missing path of an absolute-form URI.
     */
    private static String expectedUri(String uri) {
        if (uri.isEmpty()) {
            return "/";
        }
        int schemeEnd = uri.indexOf("://");
        if (schemeEnd == -1 || uri.charAt(0) == '/') {
            return uri;
        }
        int authorityStart = schemeEnd + 3;
        int query = uri.indexOf('?', authorityStart);
        int authorityEnd = query == -1 ? uri.length() : query;
        int slash = uri.indexOf('/', authorityStart);
        if (slash != -1 && slash < authorityEnd) {
            return uri;
        }
        return uri.substring(0, authorityEnd) + '/' + uri.substring(authorityEnd);
    }

    private static boolean allValid(HttpHeaders headers) {
        for (Iterator<Map.Entry<CharSequence, CharSequence>> it = headers.iteratorCharSequence(); it.hasNext(); ) {
            Map.Entry<CharSequence, CharSequence> entry = it.next();
            if (!isValidHeader(entry.getKey(), entry.getValue())) {
                return false;
            }
        }
        return true;
    }

    private static List<Map.Entry<String, String>> expectedHeaders(HttpHeaders headers, boolean trailers) {
        List<Map.Entry<String, String>> result = new ArrayList<>();
        for (Iterator<Map.Entry<CharSequence, CharSequence>> it = headers.iteratorCharSequence(); it.hasNext(); ) {
            Map.Entry<CharSequence, CharSequence> entry = it.next();
            if (trailers && isProhibitedTrailer(entry.getKey())) {
                continue;
            }
            result.add(new AbstractMap.SimpleImmutableEntry<>(
                entry.getKey().toString(),
                // the decoder trims optional whitespace around the value
                stripTrailingOws(asLatin1(entry.getValue()))));
        }
        return result;
    }

    private static List<Map.Entry<String, String>> decodedHeaders(HttpHeaders headers) {
        List<Map.Entry<String, String>> result = new ArrayList<>();
        for (Map.Entry<String, String> entry : headers) {
            result.add(new AbstractMap.SimpleImmutableEntry<>(entry.getKey(), entry.getValue()));
        }
        return result;
    }

    /**
     * Header values are written one byte per char, with '?' for chars that don't fit (see AsciiString.c2b).
     */
    private static String asLatin1(CharSequence s) {
        StringBuilder builder = new StringBuilder(s.length());
        for (int i = 0; i < s.length(); i++) {
            char c = s.charAt(i);
            builder.append(c > 0xFF ? '?' : c);
        }
        return builder.toString();
    }

    private static String stripTrailingOws(String s) {
        int end = s.length();
        while (end > 0 && (s.charAt(end - 1) == ' ' || s.charAt(end - 1) == '\t')) {
            end--;
        }
        return s.substring(0, end);
    }

    private static boolean isProhibitedTrailer(CharSequence name) {
        return HttpHeaderNames.CONTENT_LENGTH.contentEqualsIgnoreCase(name)
            || HttpHeaderNames.TRANSFER_ENCODING.contentEqualsIgnoreCase(name)
            || HttpHeaderNames.TRAILER.contentEqualsIgnoreCase(name);
    }

    private static boolean isValidHeader(CharSequence name, CharSequence value) {
        return isToken(name) && isValidHeaderValue(value);
    }

    /**
     * RFC 9110 token: 1*tchar.
     */
    private static boolean isToken(CharSequence s) {
        if (s.isEmpty()) {
            return false;
        }
        for (int i = 0; i < s.length(); i++) {
            char c = s.charAt(i);
            boolean tchar = c >= '0' && c <= '9' || c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z'
                || TCHAR_SYMBOLS.indexOf(c) != -1;
            if (!tchar) {
                return false;
            }
        }
        return true;
    }

    /**
     * RFC 9110 field-value: no CTLs except HTAB inside, and no leading whitespace. Netty also accepts chars above
     * 0xFF (they are encoded as '?'), and does not reject trailing whitespace.
     */
    private static boolean isValidHeaderValue(CharSequence s) {
        for (int i = 0; i < s.length(); i++) {
            char c = s.charAt(i);
            boolean ctl = c < 0x20 && (c != '\t' || i == 0) || c == 0x7F || i == 0 && c == ' ';
            if (ctl) {
                return false;
            }
        }
        return true;
    }

    /**
     * Netty only rejects the chars that would split the request line.
     */
    private static boolean isSafeRequestTarget(String uri) {
        return uri.indexOf(' ') == -1 && uri.indexOf('\r') == -1 && uri.indexOf('\n') == -1;
    }

    private static boolean isStrictVersion(String text) {
        return text.length() == 8 && text.startsWith("HTTP/") && Character.isDigit(text.charAt(5))
            && text.charAt(6) == '.' && Character.isDigit(text.charAt(7));
    }

    private static boolean hasNoControlOrSpace(byte[] bytes) {
        for (byte b : bytes) {
            if ((b & 0xFF) <= ' ' || b == 0x7F) {
                return false;
            }
        }
        return true;
    }

    private static String escape(CharSequence s) {
        StringBuilder builder = new StringBuilder("\"");
        for (int i = 0; i < s.length(); i++) {
            char c = s.charAt(i);
            if (c < 0x20 || c >= 0x7F) {
                builder.append(String.format("\\u%04x", (int) c));
            } else {
                builder.append(c);
            }
        }
        return builder.append('"').toString();
    }

    public static void main(String[] args) {
        LocalJazzerRunner.create(HttpRequestEncoderFuzzer.class).fuzz();
    }

    /**
     * Decoder that exposes the number of buffered bytes it has not decoded yet.
     */
    private static final class CheckedDecoder extends HttpRequestDecoder {
        CheckedDecoder() {
            super(new HttpDecoderConfig()
                .setMaxInitialLineLength(MAX_DECODER_LINE_LENGTH)
                .setMaxHeaderSize(MAX_DECODER_LINE_LENGTH));
        }

        int leftover() {
            return actualReadableBytes();
        }
    }

    private record ExpectedRequest(
        String method,
        String uri,
        String version,
        List<Map.Entry<String, String>> headers,
        byte[] body,
        List<Map.Entry<String, String>> trailers
    ) {
    }
}
