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
import io.micronaut.fuzzing.Dict;
import io.micronaut.fuzzing.DictResource;
import io.micronaut.fuzzing.FuzzTarget;
import io.micronaut.fuzzing.runner.LocalJazzerRunner;
import io.micronaut.fuzzing.sanitizer.SanitizerTransformer;
import io.micronaut.fuzzing.util.ByteSplitter;
import io.netty.buffer.ByteBuf;
import io.netty.buffer.Unpooled;

/**
 * Fuzz target for Netty's HPACK decoder.
 */
@FuzzTarget
@Dict("SEP")
@DictResource("dictionaries/hpack.dict")
public class HpackDecoderFuzzer {
    private static final long MAX_HEADER_LIST_SIZE = 8192;
    private static final ByteSplitter SPLITTER = ByteSplitter.create("SEP");

    static {
        SanitizerTransformer.installLocally();
    }

    public static void fuzzerTestOneInput(FuzzedDataProvider fuzzedDataProvider) throws Exception {
        HpackDecoder decoder = new HpackDecoder(MAX_HEADER_LIST_SIZE);
        Http2Headers headers = new DefaultHttp2Headers();
        byte[] allBytes = fuzzedDataProvider.consumeRemainingAsBytes();
        ByteSplitter.ChunkIterator itr = SPLITTER.splitIterator(allBytes);

        while (itr.hasNext()) {
            itr.proceed();
            ByteBuf buffer = Unpooled.wrappedBuffer(allBytes, itr.start(), itr.length());
            try {
                decoder.decode(1, buffer, headers, true);
                headers.clear();
            } catch (Http2Exception | IllegalArgumentException e) {
                return;
            } finally {
                buffer.release();
            }
        }
    }

    public static void main(String[] args) {
        LocalJazzerRunner.create(HpackDecoderFuzzer.class).fuzz();
    }
}
