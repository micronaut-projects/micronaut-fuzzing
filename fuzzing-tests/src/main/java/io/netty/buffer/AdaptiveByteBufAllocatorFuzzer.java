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

/**
 * Fuzzes single-threaded adaptive allocator operations.
 */
@FuzzTarget
public final class AdaptiveByteBufAllocatorFuzzer extends ByteBufAllocatorFuzzerBase {
    // Shared by all inputs: every instance registers its own thread-local magazines and keeps its own chunks.
    // Thread-local magazines are enabled for non-event-loop threads, so that the fuzzer exercises them.
    private static final AdaptiveByteBufAllocator ALLOCATOR = new AdaptiveByteBufAllocator(false, true);

    private AdaptiveByteBufAllocatorFuzzer() {
        super(ALLOCATOR);
    }

    public static void fuzzerTestOneInput(FuzzedDataProvider provider) {
        new AdaptiveByteBufAllocatorFuzzer().test(provider);
    }

    public static void main(String[] args) {
        LocalJazzerRunner.create(AdaptiveByteBufAllocatorFuzzer.class).fuzz();
    }
}
