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
package io.netty.handler.codec.compression;

import com.code_intelligence.jazzer.api.FuzzedDataProvider;
import com.ning.compress.lzf.LZFException;
import io.micronaut.fuzzing.FuzzTarget;
import io.micronaut.fuzzing.HttpDict;
import io.micronaut.fuzzing.runner.LocalJazzerRunner;
import io.netty.channel.embedded.EmbeddedChannel;
import io.netty.handler.codec.DecoderException;


/**
 * Fuzzing support type.
 */
@FuzzTarget
@HttpDict
public class LzfDecoderFuzzer extends DecompressorFuzzerBase {
    private final boolean safeInstance;

    public LzfDecoderFuzzer(boolean safeInstance) {
        this.safeInstance = safeInstance;
    }

    @Override
    protected EmbeddedChannel setUp() {
        EmbeddedChannel channel = new EmbeddedChannel();
        channel.pipeline()
            .addLast(new LzfDecoder(safeInstance));
        return channel;
    }

    @Override
    protected void onException(Exception e) {
        if (isCorruptChunk(e)) {
            return;
        }
        super.onException(e);
    }

    /**
     * {@link LzfDecoder} does not wrap the exceptions of compress-lzf in a {@link DecompressionException}, so
     * {@code ByteToMessageDecoder} wraps them in a {@link DecoderException}. Since compress-lzf 1.2.1, the chunk
     * decoders check the bounds of corrupt input and throw an {@link LZFException} instead of reading out of bounds.
     *
     * @param e The exception
     * @return {@code true} if the exception is an {@link LZFException} for a corrupt chunk
     */
    static boolean isCorruptChunk(Exception e) {
        if (!(e instanceof DecoderException) || !(e.getCause() instanceof LZFException cause)) {
            return false;
        }
        StackTraceElement[] trace = cause.getStackTrace();
        if (trace.length == 0) {
            return false;
        }
        String className = trace[0].getClassName();
        return trace[0].getMethodName().equals("decodeChunk")
            && (className.equals("com.ning.compress.lzf.impl.VanillaChunkDecoder")
            || className.equals("com.ning.compress.lzf.impl.UnsafeChunkDecoder"));
    }

    public static void fuzzerTestOneInput(FuzzedDataProvider fuzzedDataProvider) {
        boolean safeInstance = fuzzedDataProvider.consumeBoolean();
        new LzfDecoderFuzzer(safeInstance).test(fuzzedDataProvider);
    }

    public static void main(String[] args) {
        LocalJazzerRunner.create(LzfDecoderFuzzer.class).fuzz();
    }
}
