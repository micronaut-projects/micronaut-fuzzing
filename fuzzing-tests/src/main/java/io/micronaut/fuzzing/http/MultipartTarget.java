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
package io.micronaut.fuzzing.http;

import com.code_intelligence.jazzer.api.FuzzedDataProvider;
import io.micronaut.fuzzing.Dict;
import io.micronaut.fuzzing.FuzzTarget;
import io.micronaut.fuzzing.HttpDict;
import io.micronaut.http.HttpStatus;
import io.micronaut.http.MediaType;
import io.micronaut.http.body.stream.BodySizeLimits;
import io.micronaut.http.exceptions.ContentLengthExceededException;
import io.micronaut.http.exceptions.HttpStatusException;
import io.micronaut.http.multipart.RawFormField;
import io.micronaut.http.netty.body.NettyByteBodyFactory;
import io.micronaut.http.server.netty.multipart.FormDemuxer;
import io.netty.buffer.Unpooled;
import io.netty.channel.embedded.EmbeddedChannel;
import io.netty.contrib.multipart.FormDecoderException;
import io.netty.contrib.multipart.PostBodyDecoder;
import reactor.core.publisher.Flux;

import java.nio.charset.StandardCharsets;

/**
 * Fuzzing support type.
 */
@FuzzTarget
@HttpDict
@Dict({
    "multipart/form-data; boundary=",
    "Content-Disposition: form-data; name=\"",
    "Content-Disposition: form-data; name=\"file\"; filename=\"",
    "Content-Type: application/octet-stream",
    "Content-Type: image/jpeg",
    "Content-Type: text/plain",
    "--boundary",
    "--boundary--",
    "\r\n\r\n",
    SimpleController.UPLOAD_FILE,
    SimpleController.UPLOAD_FIELDS,
    SimpleController.UPLOAD_MIXED,
})
public class MultipartTarget {

    private static final EmbeddedChannel CHANNEL = new EmbeddedChannel();
    private static final NettyByteBodyFactory BYTE_BODY_FACTORY = new NettyByteBodyFactory(CHANNEL);

    public static void fuzzerTestOneInput(FuzzedDataProvider data) {
        String boundary = sanitizeBoundary(data.consumeString(40));
        int partCount = data.consumeInt(1, 5);
        StringBuilder body = new StringBuilder();
        for (int i = 0; i < partCount; i++) {
            String partBoundary = data.consumeBoolean() ? boundary : data.consumeString(20);
            body.append("--").append(partBoundary).append("\r\n");
            String partName = data.consumeString(20);
            boolean isFile = data.consumeBoolean();
            if (isFile) {
                String filename = data.consumeString(30);
                body.append("Content-Disposition: form-data; name=\"").append(partName).append("\"; filename=\"").append(filename).append("\"\r\n");
                String ct = data.pickValue(new String[]{"image/jpeg", "application/octet-stream", "text/plain", data.consumeString(30)});
                body.append("Content-Type: ").append(ct).append("\r\n");
            } else {
                body.append("Content-Disposition: form-data; name=\"").append(partName).append("\"\r\n");
            }
            body.append("\r\n");
            String content = data.consumeBoolean() ? data.consumeRemainingAsString() : "--" + boundary + data.consumeString(10);
            body.append(content).append("\r\n");
        }
        body.append("--").append(boundary).append("--\r\n");

        decode(boundary, body.toString().getBytes(StandardCharsets.ISO_8859_1));
    }

    /**
     * Decode a multipart body, ignoring the failures for a malformed body.
     *
     * @param boundary  The boundary
     * @param bodyBytes The body
     */
    static void decode(String boundary, byte[] bodyBytes) {
        PostBodyDecoder decoder = PostBodyDecoder.builder().forMultipartBoundary(boundary);
        try {
            // fields() returns a Publisher since micronaut-core 5.3
            Flux.from(new FormDemuxer(decoder, boundary, StandardCharsets.UTF_8, CHANNEL, BodySizeLimits.UNLIMITED, BodySizeLimits.UNLIMITED,
                    BYTE_BODY_FACTORY.adapt(Unpooled.wrappedBuffer(bodyBytes)))
                    .fields())
                .doOnNext(RawFormField::close)
                .blockLast();
        } catch (FormDecoderException | ContentLengthExceededException ignored) {
        } catch (HttpStatusException e) {
            if (!isMalformedBody(e)) {
                throw e;
            }
        } catch (IllegalArgumentException e) {
            // FormDemuxer parses the Content-Type and Content-Length of a part with MediaType.of
            // and Long.parseLong, which throw for an invalid value, instead of refusing the body
            // as malformed
            if (!isThrownByHeaderParsing(e, MediaType.class.getName(), "of")
                && !(e instanceof NumberFormatException && isThrownByHeaderParsing(e, Long.class.getName(), "parseLong"))) {
                throw e;
            }
        }
    }

    /**
     * Whether the exception is thrown by the given method, called by {@link FormDemuxer} to parse
     * the header of a part.
     *
     * @param e         The exception
     * @param className The class of the method
     * @param method    The name of the method
     * @return {@code true} if the method threw the exception for the header
     */
    static boolean isThrownByHeaderParsing(Throwable e, String className, String method) {
        StackTraceElement[] stackTrace = e.getStackTrace();
        for (int i = 1; i < stackTrace.length; i++) {
            if (stackTrace[i].getClassName().equals(FormDemuxer.class.getName() + "$Headers") && stackTrace[i].getMethodName().equals("accept")) {
                return stackTrace[i - 1].getClassName().equals(className) && stackTrace[i - 1].getMethodName().equals(method);
            }
        }
        return false;
    }

    /**
     * Whether the exception is how {@link FormDemuxer} refuses a malformed body: a decoder
     * failure wrapped in a bad request, or a multipart body that ends before its closing
     * boundary, which {@link FormDemuxer#complete()} refuses.
     *
     * @param e The exception
     * @return {@code true} if the body is malformed
     */
    static boolean isMalformedBody(HttpStatusException e) {
        if (e.getStatus() != HttpStatus.BAD_REQUEST) {
            return false;
        }
        if (e.getCause() != null) {
            return e.getCause() instanceof FormDecoderException;
        }
        StackTraceElement[] stackTrace = e.getStackTrace();
        return stackTrace.length > 0
            && stackTrace[0].getClassName().equals(FormDemuxer.class.getName())
            && stackTrace[0].getMethodName().equals("complete");
    }

    private static String sanitizeBoundary(String raw) {
        if (raw == null || raw.isEmpty()) {
            return "fuzzBoundary";
        }
        String clean = raw.replaceAll("[^a-zA-Z0-9'()+_,-./:=?]", "x");
        return clean.isEmpty() ? "fuzzBoundary" : clean;
    }
}
