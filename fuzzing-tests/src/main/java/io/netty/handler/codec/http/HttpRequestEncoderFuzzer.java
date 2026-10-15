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
import io.netty.handler.codec.EncoderException;
import io.netty.util.AsciiString;
import io.netty.util.LeakPresenceDetector;
import io.netty.util.ReferenceCountUtil;
import io.netty.util.concurrent.FastThreadLocalThread;
import io.netty.util.internal.StringUtil;

import java.io.ByteArrayOutputStream;
import java.nio.charset.StandardCharsets;
import java.util.AbstractMap;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Iterator;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Objects;

/**
 * Fuzzes {@link HttpRequestEncoder} with message sequences (several requests per channel, each either a
 * {@link FullHttpRequest} or an {@link HttpRequest} followed by content and a {@link LastHttpContent}), built from
 * raw method, URI, version, header and body input.
 * <p>
 * Oracles:
 * <ul>
 *     <li>Method, URI, version and header validation must accept exactly the values that can be encoded safely. A
 *     value that slips past validation can inject data into the encoded request.</li>
 *     <li>Occasionally, a message that is not valid in the current encoder state is written (content before the
 *     request, or a second request before the last content). The encoder must reject exactly that message with its
 *     state error, release it, and keep working.</li>
 *     <li>The output of each request that can round trip is compared byte by byte to the expected wire format, and
 *     fed to one long-lived {@link HttpRequestDecoder}, which must decode the same method, URI, version, headers,
 *     body and trailers, and nothing else.</li>
 * </ul>
 * Requests that cannot round trip are still encoded, but their output is not checked or decoded, so they don't affect
 * the check of the following requests. These are:
 * <ul>
 *     <li>Requests with invalid headers or trailers. They are only possible with validation off, and may contain
 *     CRLF.</li>
 *     <li>Versions that are not of the form {@code HTTP/x.y}, which the decoder rejects.</li>
 *     <li>Requests whose framing headers don't match the body, or that the decoder frames differently.</li>
 *     <li>URIs with control characters or whitespace. This is a deliberate exclusion: request line validation only
 *     rejects SP, CR and LF, but the decoder also splits the request line on HTAB, VT and FF and rejects other
 *     control characters. Such requests are rejected by the decoder, but they cannot make it accept a different
 *     request: the version token runs to the end of the line and then fails strict version parsing. This target
 *     does not detect request line desynchronization through these characters.</li>
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
    "\t", " ", "\r", "\n", "\r\n", ":", "ÿ", "Ā", "Ċ"
})
public final class HttpRequestEncoderFuzzer {
    static final int MAX_REQUESTS = 4;
    static final int MAX_HEADERS = 8;
    static final int MAX_TRAILERS = 4;
    static final int MAX_CHUNKS = 4;
    private static final int MAX_VERSION_LENGTH = 16;
    private static final int MAX_METHOD_LENGTH = 32;
    private static final int MAX_URI_LENGTH = 256;
    private static final int MAX_HEADER_NAME_LENGTH = 64;
    private static final int MAX_HEADER_VALUE_LENGTH = 256;
    private static final int MAX_BODY_LENGTH = 512;

    private static final int FRAMING_CONTENT_LENGTH = 0;
    private static final int FRAMING_CHUNKED = 1;
    private static final int FRAMING_NONE = 2;

    private static final int CHUNK_HTTP_CONTENT = 0;
    private static final int CHUNK_BYTE_BUF = 1;
    private static final int CHUNK_EMPTY_BUFFER = 2;

    private static final int MISPLACED_NONE = 0;
    private static final int MISPLACED_CONTENT = 1;
    private static final int MISPLACED_LAST_CONTENT = 2;
    private static final int MISPLACED_EMPTY_LAST_CONTENT = 3;
    private static final int MISPLACED_BYTE_BUF = 4;
    private static final int MISPLACED_REQUEST = 5;
    private static final int MISPLACED_FULL_REQUEST = 6;

    /**
     * See {@code HttpObjectEncoder.ST_INIT} and the following constants.
     */
    private static final int STATE_INIT = 0;
    private static final int STATE_CONTENT_NON_CHUNK = 1;
    private static final int STATE_CONTENT_CHUNK = 2;

    private static final String TCHAR_SYMBOLS = "!#$%&'*+-.^_`|~";
    private static final byte[] CRLF = {'\r', '\n'};

    static {
        // not done by EmbeddedChannelFuzzerBase, since this target does not extend it
        SanitizerTransformer.installLocally();
    }

    private final FuzzedDataProvider data;
    private EmbeddedChannel encoderChannel;
    private EmbeddedChannel decoderChannel;
    private ByteBufAllocator alloc;
    private int roundTrips;

    private HttpRequestEncoderFuzzer(FuzzedDataProvider data) {
        this.data = data;
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
        HttpRequestEncoderFuzzer fuzzer = new HttpRequestEncoderFuzzer(data);
        FastThreadLocalThread.runWithFastThreadLocal(() -> {
            fuzzer.run();
            LeakPresenceDetector.check();
            FlagAppender.checkTriggered();
        });
        return fuzzer.roundTrips;
    }

    private void run() {
        // encoders and decoders are not @Sharable and keep state, so create fresh ones for each input. The default
        // decoder limits (4096 for the initial line, 8192 for the headers) are well above what writeRequest generates
        encoderChannel = new EmbeddedChannel(new HttpRequestEncoder());
        decoderChannel = new EmbeddedChannel(new HttpRequestDecoder());
        alloc = encoderChannel.alloc();
        try {
            int requestCount = data.consumeInt(1, MAX_REQUESTS);
            for (int i = 0; i < requestCount; i++) {
                writeRequest();
            }
        } finally {
            encoderChannel.finishAndReleaseAll();
            decoderChannel.finishAndReleaseAll();
        }
    }

    private void writeRequest() {
        int noise = data.consumeInt(0, 2);
        int misplaced = data.consumeInt(MISPLACED_NONE, MISPLACED_FULL_REQUEST);
        int versionChoice = data.consumeInt(0, 2);
        String versionText = versionChoice == 2 ? data.consumeString(MAX_VERSION_LENGTH) : null;
        String methodName = data.consumeString(MAX_METHOD_LENGTH);
        String uri = data.consumeString(MAX_URI_LENGTH);
        boolean validate = data.consumeBoolean();
        boolean full = data.consumeBoolean();
        int framing = data.consumeInt(FRAMING_CONTENT_LENGTH, FRAMING_NONE);
        int headerCount = data.consumeInt(0, MAX_HEADERS);
        int framingPosition = data.consumeInt(0, headerCount);
        List<CharSequence[]> headers = consumeHeaders(headerCount);

        byte[] fullBody = null;
        List<Chunk> chunks = new ArrayList<>();
        byte[] lastChunk = null;
        if (full) {
            fullBody = data.consumeBytes(MAX_BODY_LENGTH);
        } else {
            int chunkCount = data.consumeInt(0, MAX_CHUNKS);
            for (int i = 0; i < chunkCount; i++) {
                int kind = data.consumeInt(CHUNK_HTTP_CONTENT, CHUNK_EMPTY_BUFFER);
                chunks.add(new Chunk(kind, kind == CHUNK_EMPTY_BUFFER ? new byte[0] : data.consumeBytes(MAX_BODY_LENGTH)));
            }
            if (data.consumeBoolean()) {
                lastChunk = data.consumeBytes(MAX_BODY_LENGTH);
            }
        }
        List<CharSequence[]> trailers = full || lastChunk != null
            ? consumeHeaders(data.consumeInt(0, MAX_TRAILERS))
            : List.of();

        HttpVersion version = parseVersion(versionChoice, versionText);
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
            chunks.forEach(chunk -> body.writeBytes(chunk.bytes()));
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

        // compute these before writing, the encoder releases the messages
        ExpectedRequest expected = expectedRequest(request, body.toByteArray(), trailingHeaders);
        int contentState = HttpUtil.isTransferEncodingChunked(request) ? STATE_CONTENT_CHUNK : STATE_CONTENT_NON_CHUNK;

        switch (noise) {
            case 1 -> encoderChannel.writeOutbound(Unpooled.EMPTY_BUFFER);
            case 2 -> encoderChannel.writeOutbound(alloc.buffer(0));
            default -> {
            }
        }
        switch (misplaced) {
            case MISPLACED_CONTENT -> writeMisplaced(new DefaultHttpContent(alloc.buffer(1).writeByte('x')), STATE_INIT);
            case MISPLACED_LAST_CONTENT ->
                writeMisplaced(new DefaultLastHttpContent(alloc.buffer(1).writeByte('x')), STATE_INIT);
            case MISPLACED_EMPTY_LAST_CONTENT -> writeMisplaced(LastHttpContent.EMPTY_LAST_CONTENT, STATE_INIT);
            case MISPLACED_BYTE_BUF -> writeMisplaced(alloc.buffer(1).writeByte('x'), STATE_INIT);
            default -> {
            }
        }
        encoderChannel.writeOutbound(request);
        if (!full) {
            switch (misplaced) {
                case MISPLACED_REQUEST ->
                    writeMisplaced(new DefaultHttpRequest(HttpVersion.HTTP_1_1, HttpMethod.GET, "/"), contentState);
                case MISPLACED_FULL_REQUEST -> writeMisplaced(new DefaultFullHttpRequest(
                    HttpVersion.HTTP_1_1, HttpMethod.GET, "/", alloc.buffer(1).writeByte('x')), contentState);
                default -> {
                }
            }
            for (Chunk chunk : chunks) {
                byte[] bytes = chunk.bytes();
                switch (chunk.kind()) {
                    case CHUNK_HTTP_CONTENT ->
                        encoderChannel.writeOutbound(new DefaultHttpContent(alloc.buffer(bytes.length).writeBytes(bytes)));
                    case CHUNK_BYTE_BUF -> encoderChannel.writeOutbound(alloc.buffer(bytes.length).writeBytes(bytes));
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

    /**
     * Write a message that is not valid in the current encoder state, and check that the encoder rejects it with its
     * state error. The encoder releases the message and does not change its state.
     */
    private void writeMisplaced(Object message, int state) {
        String expectedMessage = "unexpected message type: " + StringUtil.simpleClassName(message) + ", state: " + state;
        try {
            encoderChannel.writeOutbound(message);
        } catch (EncoderException e) {
            Throwable cause = e.getCause();
            if (e.getClass() == EncoderException.class && cause != null
                && cause.getClass() == IllegalStateException.class && expectedMessage.equals(cause.getMessage())) {
                return;
            }
            throw e;
        }
        throw new AssertionError("Encoder accepted a misplaced message, expected: " + expectedMessage);
    }

    /**
     * Parse a version, and check that it is rejected exactly when it is invalid.
     *
     * @param choice 0 for HTTP/1.0, 1 for HTTP/1.1, 2 to parse the text
     * @param text The version text
     * @return The version, or {@code null} if it was rejected
     */
    private static HttpVersion parseVersion(int choice, String text) {
        if (choice == 0) {
            return HttpVersion.HTTP_1_0;
        } else if (choice == 1) {
            return HttpVersion.HTTP_1_1;
        }
        HttpVersion version;
        try {
            version = HttpVersion.valueOf(text);
        } catch (IllegalArgumentException e) {
            expectRejected(e, isLenientVersion(text), "version", text);
            return null;
        }
        if (!isLenientVersion(text)) {
            throw new AssertionError("Invalid version accepted: " + escape(text));
        }
        String encoded = version.text();
        for (int i = 0; i < encoded.length(); i++) {
            char c = encoded.charAt(i);
            if (Character.isISOControl(c) || Character.isWhitespace(c)) {
                throw new AssertionError("Version contains whitespace or control chars: " + escape(encoded));
            }
        }
        return version;
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
        String what = trailer ? "trailer" : "header";
        try {
            headers.add(name, value);
        } catch (IllegalArgumentException e) {
            // without validation, nothing may be rejected
            expectRejected(e, valid || !validate, what, name + ": " + value);
            return;
        }
        if (validate && !valid) {
            throw new AssertionError("Invalid " + what + " accepted: " + escape(name) + ": " + escape(value));
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
     * Determine what the encoder should write and the decoder should see for this request.
     *
     * @return The expected request, or {@code null} if this request can't round trip
     */
    private static ExpectedRequest expectedRequest(HttpRequest request, byte[] body, HttpHeaders trailingHeaders) {
        String version = request.protocolVersion().text();
        // the decoder only accepts this version format
        if (!isStrictVersion(version)
            // see the class javadoc
            || !hasNoControlOrSpace(request.uri().getBytes(StandardCharsets.UTF_8))
            // with validation off, the header may be anything, including CRLF
            || !allValid(request.headers())) {
            return null;
        }
        Boolean chunked = chunked(request, body.length);
        if (chunked == null || chunked && !allValid(trailingHeaders)) {
            return null;
        }

        ByteArrayOutputStream head = new ByteArrayOutputStream();
        byte[] uriBytes = expectedUri(request.uri()).getBytes(StandardCharsets.UTF_8);
        String uri = new String(uriBytes, StandardCharsets.ISO_8859_1);
        head.writeBytes((request.method().name() + ' ' + uri + ' ' + version).getBytes(StandardCharsets.ISO_8859_1));
        head.writeBytes(CRLF);
        writeHeaderLines(head, request.headers());
        ByteArrayOutputStream trailerSection = new ByteArrayOutputStream();
        if (chunked) {
            writeHeaderLines(trailerSection, trailingHeaders);
        }

        return new ExpectedRequest(
            head.toByteArray(),
            chunked,
            trailerSection.toByteArray(),
            request.method().name(),
            uri,
            version,
            expectedHeaders(request.headers(), false),
            body,
            // trailers only exist in chunked encoding, the encoder drops them otherwise. The decoder drops prohibited
            // trailers, which are only possible when validation is off
            chunked ? expectedHeaders(trailingHeaders, true) : List.of()
        );
    }

    /**
     * Write the header lines the way HttpHeadersEncoder does, followed by the empty line.
     */
    private static void writeHeaderLines(ByteArrayOutputStream out, HttpHeaders headers) {
        for (Iterator<Map.Entry<CharSequence, CharSequence>> it = headers.iteratorCharSequence(); it.hasNext(); ) {
            Map.Entry<CharSequence, CharSequence> entry = it.next();
            String line = asLatin1(entry.getKey()) + ": " + asLatin1(entry.getValue());
            out.writeBytes(line.getBytes(StandardCharsets.ISO_8859_1));
            out.writeBytes(CRLF);
        }
        out.writeBytes(CRLF);
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
        ByteArrayOutputStream wire = new ByteArrayOutputStream();
        for (Object encoded; (encoded = encoderChannel.readOutbound()) != null; ) {
            wire.writeBytes(ByteBufUtil.getBytes((ByteBuf) encoded));
            decoderChannel.writeInbound(encoded);
        }
        // the decoder skips whitespace between requests, so check the exact bytes too
        checkWireFormat(exp, wire.toByteArray());

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
        checkBody(exp.body(), body.toByteArray());
        Object extra = decoderChannel.readInbound();
        if (extra != null) {
            ReferenceCountUtil.release(extra);
            throw new AssertionError("Unexpected extra decoded message: " + extra);
        }
    }

    /**
     * Check that the encoder output is exactly the expected head, followed by the body in the expected framing.
     */
    private static void checkWireFormat(ExpectedRequest exp, byte[] wire) {
        byte[] head = exp.head();
        if (!startsWith(wire, 0, head)) {
            throw new AssertionError("Head mismatch: expected " + escapeLatin1(head, 0, head.length)
                + ", encoded " + escapeLatin1(wire, 0, wire.length));
        }
        int pos = head.length;
        if (!exp.chunked()) {
            checkBody(exp.body(), Arrays.copyOfRange(wire, pos, wire.length));
            return;
        }
        ByteArrayOutputStream body = new ByteArrayOutputStream();
        while (true) {
            int lineEnd = indexOfCrlf(wire, pos);
            String size = lineEnd == -1 ? "" : new String(wire, pos, lineEnd - pos, StandardCharsets.ISO_8859_1);
            // the encoder writes the size in minimal lower case hex, without extensions
            if (!size.matches("0|[1-9a-f][0-9a-f]{0,6}")) {
                throw new AssertionError("Bad chunk size line at " + pos + ": " + escapeLatin1(wire, 0, wire.length));
            }
            int chunkSize = Integer.parseInt(size, 16);
            pos = lineEnd + CRLF.length;
            if (chunkSize == 0) {
                break;
            }
            if (wire.length - pos < chunkSize + CRLF.length || !startsWith(wire, pos + chunkSize, CRLF)) {
                throw new AssertionError("Bad chunk at " + pos + ": " + escapeLatin1(wire, 0, wire.length));
            }
            body.write(wire, pos, chunkSize);
            pos += chunkSize + CRLF.length;
        }
        byte[] trailers = exp.trailerSection();
        if (wire.length - pos != trailers.length || !startsWith(wire, pos, trailers)) {
            throw new AssertionError("Trailer section mismatch: expected "
                + escapeLatin1(trailers, 0, trailers.length) + ", encoded " + escapeLatin1(wire, pos, wire.length));
        }
        checkBody(exp.body(), body.toByteArray());
    }

    private static boolean startsWith(byte[] array, int offset, byte[] prefix) {
        return array.length - offset >= prefix.length
            && Arrays.equals(array, offset, offset + prefix.length, prefix, 0, prefix.length);
    }

    private static int indexOfCrlf(byte[] array, int from) {
        for (int i = from; i < array.length - 1; i++) {
            if (array[i] == '\r' && array[i + 1] == '\n') {
                return i;
            }
        }
        return -1;
    }

    private static String escapeLatin1(byte[] array, int from, int to) {
        return escape(new String(array, from, to - from, StandardCharsets.ISO_8859_1));
    }

    private static void checkBody(byte[] expected, byte[] actual) {
        if (!Arrays.equals(expected, actual)) {
            throw new AssertionError("Body mismatch: expected " + Arrays.toString(expected)
                + ", got " + Arrays.toString(actual));
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
     * Header names and values are written one byte per char, with '?' for chars that don't fit (see
     * AsciiString.c2b).
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

    /**
     * The lenient version format that {@link HttpVersion#valueOf(String)} accepts: {@code protocol/major.minor}, case
     * insensitive, with a protocol name without whitespace or control chars, and decimal version numbers.
     */
    private static boolean isLenientVersion(String text) {
        String upper = text.toUpperCase(Locale.US);
        int slash = upper.indexOf('/');
        int dot = upper.indexOf('.', slash + 1);
        if (slash <= 0 || dot <= slash + 1 || dot >= upper.length() - 1) {
            return false;
        }
        for (int i = 0; i < slash; i++) {
            char c = upper.charAt(i);
            if (Character.isISOControl(c) || Character.isWhitespace(c)) {
                return false;
            }
        }
        for (int i = slash + 1; i < upper.length(); i++) {
            char c = upper.charAt(i);
            if (i != dot && (c < '0' || c > '9')) {
                return false;
            }
        }
        return true;
    }

    /**
     * The version format that the decoder accepts.
     */
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

    private record Chunk(int kind, byte[] bytes) {
    }

    /**
     * @param head The expected request line and header section, including the empty line
     * @param chunked Whether the body is chunked
     * @param trailerSection The expected trailer lines after the last chunk, including the empty line
     * @param method The expected decoded method
     * @param uri The expected decoded URI
     * @param version The expected decoded version
     * @param headers The expected decoded headers
     * @param body The expected body
     * @param trailers The expected decoded trailers
     */
    private record ExpectedRequest(
        byte[] head,
        boolean chunked,
        byte[] trailerSection,
        String method,
        String uri,
        String version,
        List<Map.Entry<String, String>> headers,
        byte[] body,
        List<Map.Entry<String, String>> trailers
    ) {
    }
}
