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
package io.netty.buffer;

import com.code_intelligence.jazzer.api.FuzzedDataProvider;
import io.micronaut.fuzzing.FuzzTarget;
import io.micronaut.fuzzing.runner.LocalJazzerRunner;

import java.lang.reflect.Field;

/**
 * Fuzzes single-threaded adaptive allocator operations.
 */
@FuzzTarget
public final class AdaptiveByteBufAllocatorFuzzer extends ByteBufAllocatorFuzzerBase {
    private static final String LOW_MEMORY_PROPERTY = "io.netty.allocator.lowMemory";

    static {
        // AdaptivePoolingAllocator considers a max heap of 512M or less (as used on OSS-Fuzz) low memory, and then
        // disables the thread-local and large buffer magazine groups. Keep them enabled so that they are fuzzed. This
        // must run before AdaptivePoolingAllocator is initialized.
        System.setProperty(LOW_MEMORY_PROPERTY, "false");
        if (isLowMemory()) {
            throw new IllegalStateException("AdaptivePoolingAllocator was initialized before " + LOW_MEMORY_PROPERTY + " was set");
        }
    }

    // Shared by all inputs: every instance registers its own thread-local magazines and keeps its own chunks.
    // Thread-local magazines are enabled for non-event-loop threads, so that the fuzzer exercises them.
    // preferDirect, so that buffer() differs from heapBuffer() (where direct buffers can be freed reliably).
    private static final AdaptiveByteBufAllocator ALLOCATOR = new AdaptiveByteBufAllocator(true, true);

    private AdaptiveByteBufAllocatorFuzzer() {
        super(ALLOCATOR);
    }

    static boolean isLowMemory() {
        try {
            Field field = AdaptivePoolingAllocator.class.getDeclaredField("IS_LOW_MEM");
            field.setAccessible(true);
            return field.getBoolean(null);
        } catch (ReflectiveOperationException e) {
            throw new IllegalStateException("Cannot read AdaptivePoolingAllocator.IS_LOW_MEM", e);
        }
    }

    public static void fuzzerTestOneInput(FuzzedDataProvider provider) {
        new AdaptiveByteBufAllocatorFuzzer().test(provider);
    }

    public static void main(String[] args) {
        LocalJazzerRunner.create(AdaptiveByteBufAllocatorFuzzer.class).fuzz();
    }
}
