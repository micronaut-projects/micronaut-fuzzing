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
package io.micronaut.fuzzing;

import com.code_intelligence.jazzer.api.FuzzedDataProvider;
import io.micronaut.fuzzing.runner.LocalJazzerRunner;

@FuzzTarget(enableImplicitly = false)
public class CpuTestTarget {
    public static void fuzzerTestOneInput(FuzzedDataProvider provider) {
        long start = CpuTimer.currentThreadCpuTimeNanos();
        System.out.println(collatz(provider.consumeInt()));;
        long end = CpuTimer.currentThreadCpuTimeNanos();
        if (end > start + 1_000_000_000L) {
            throw new IllegalStateException("took too long (" + (end - start) + ")");
        }
        System.out.println("took " + (end - start));
    }

    private static int collatz(int i) {
        for (int j = 0; i != 1 && j < 10_000_000; j++) {
            if (i % 2 == 0) {
                i = i / 2;
            } else {
                i = i * 3 + 1;
            }
        }
        return i;
    }

    public static void main(String[] args) {
        LocalJazzerRunner.create(CpuTestTarget.class).fuzz();
    }
}
