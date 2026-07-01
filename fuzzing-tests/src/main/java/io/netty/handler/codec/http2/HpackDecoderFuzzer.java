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

import com.code_intelligence.jazzer.api.FuzzedDataProvider;
import io.micronaut.fuzzing.DictResource;
import io.micronaut.fuzzing.FuzzTarget;
import io.micronaut.fuzzing.runner.LocalJazzerRunner;
import io.micronaut.fuzzing.sanitizer.SanitizerTransformer;
import io.micronaut.fuzzing.util.ByteSplitter;
import io.netty.buffer.ByteBuf;
import io.netty.buffer.Unpooled;
import io.netty.util.internal.PlatformDependent;

/**
 * Fuzzes HpackDecoder directly — the HPACK header decompressor used in HTTP/2.
 * HpackDecoder is stateful: the dynamic table persists across decode() calls,
 * simulating multiple HTTP/2 HEADERS frames on the same connection.
 */
@FuzzTarget
@DictResource("dictionaries/hpack.dict")
public class HpackDecoderFuzzer {

    private static final long MAX_HEADER_LIST_SIZE = 8192;
    private static final ByteSplitter SPLITTER = ByteSplitter.create("SEP");

    static {
        SanitizerTransformer.installLocally();
    }

    public static void fuzzerTestOneInput(FuzzedDataProvider data) {
        // New decoder per run — fresh dynamic table
        HpackDecoder decoder = new HpackDecoder(MAX_HEADER_LIST_SIZE);
        Http2Headers headers = new DefaultHttp2Headers();

        byte[] allBytes = data.consumeRemainingAsBytes();
        ByteSplitter.ChunkIterator itr = SPLITTER.splitIterator(allBytes);

        // Each chunk simulates one HEADERS frame — dynamic table persists between them
        while (itr.hasNext()) {
            itr.proceed();
            ByteBuf buf = Unpooled.wrappedBuffer(allBytes, itr.start(), itr.length());
            try {
                decoder.decode(1, buf, headers, true);
                headers.clear();
            } catch (Http2Exception e) {
                // Expected for malformed HPACK blocks
                break;
            } catch (IllegalArgumentException e) {
                // Expected for incomplete/truncated HPACK blocks
                break;
            } catch (Exception e) {
                PlatformDependent.throwException(e);
            } finally {
                buf.release();
            }
        }
    }

    public static void main(String[] args) {
        LocalJazzerRunner.create(HpackDecoderFuzzer.class).fuzz();
    }
}
