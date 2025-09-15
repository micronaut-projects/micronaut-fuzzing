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
