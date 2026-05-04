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
package io.micronaut.fuzzing.sanitizer;

import com.code_intelligence.jazzer.api.FuzzedDataProvider;
import io.micronaut.fuzzing.FuzzTarget;
import io.micronaut.fuzzing.runner.LocalJazzerRunner;
import io.netty.buffer.ByteBuf;
import io.netty.buffer.ByteBufAllocator;

/**
 * Fuzzing support type.
 */
@FuzzTarget(enableImplicitly = false)
public class TestOutOfBoundsTarget {
    static {
        SanitizerTransformer.installLocally();
    }

    private static volatile byte sink;

    public static void fuzzerTestOneInput(FuzzedDataProvider provider) {
        ByteBuf buffer = ByteBufAllocator.DEFAULT.heapBuffer(16);
        try {
            byte[] array = buffer.array();
            int ix = buffer.arrayOffset() + (provider.consumeByte() & 0xff);
            sink = array[Math.min(ix, array.length - 1)];
        } finally {
            buffer.release();
        }
    }

    static void main() {
        LocalJazzerRunner.create(TestOutOfBoundsTarget.class).fuzz();
    }
}
