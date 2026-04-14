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
import io.micronaut.http.body.stream.BodySizeLimits;
import io.micronaut.http.exceptions.ContentLengthExceededException;
import io.micronaut.http.multipart.RawFormField;
import io.micronaut.http.netty.body.NettyByteBodyFactory;
import io.micronaut.http.server.netty.multipart.FormDemuxer;
import io.netty.buffer.Unpooled;
import io.netty.channel.embedded.EmbeddedChannel;
import io.netty.contrib.multipart.FormDecoderException;
import io.netty.contrib.multipart.PostBodyDecoder;

import java.nio.charset.StandardCharsets;

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

        byte[] bodyBytes = body.toString().getBytes(StandardCharsets.ISO_8859_1);
        PostBodyDecoder decoder = PostBodyDecoder.builder().forMultipartBoundary(boundary);
        try {
            new FormDemuxer(decoder, CHANNEL, BodySizeLimits.UNLIMITED, BodySizeLimits.UNLIMITED,
                BYTE_BODY_FACTORY.adapt(Unpooled.wrappedBuffer(bodyBytes)))
                .fields()
                .doOnNext(RawFormField::close)
                .blockLast();
        } catch (FormDecoderException | ContentLengthExceededException | IllegalArgumentException | IllegalStateException ignored) {
        }
    }

    private static String sanitizeBoundary(String raw) {
        if (raw == null || raw.isEmpty()) return "fuzzBoundary";
        String clean = raw.replaceAll("[^a-zA-Z0-9'()+_,-./:=?]", "x");
        return clean.isEmpty() ? "fuzzBoundary" : clean;
    }
}
