package io.micronaut.fuzzing;

import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertTrue;

class CpuTimerTest {
    @Test
    public void test() {
        long start = CpuTimer.currentThreadCpuTimeNanos();
        System.out.println("hi");
        long end = CpuTimer.currentThreadCpuTimeNanos();
        assertTrue(end - start > 1000);
    }
}
