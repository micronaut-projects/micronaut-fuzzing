package io.micronaut.fuzzing;

import com.code_intelligence.jazzer.api.FuzzedDataProvider;

public class TestTarget {
    public static void fuzzerTestOneInput(FuzzedDataProvider provider) {
        int a = provider.consumeInt();
        int b = provider.consumeInt();
        if (a > 0 && b > 0) {
            int sum = a + b;
            if (sum < 0) {
                throw new RuntimeException("failure");
            }
        }
    }
}
