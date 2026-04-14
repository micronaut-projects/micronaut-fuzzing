package io.micronaut.fuzzing;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.condition.EnabledOnOs;
import org.junit.jupiter.api.condition.OS;

import static org.junit.jupiter.api.Assertions.assertTrue;

@EnabledOnOs(OS.LINUX)
class CpuTimerTest {
    @Test
    public void measuresRealCpuTime() {
        long start = CpuTimer.currentThreadCpuTimeNanos();

        long sum = 0;
        for (int i = 0; i < 1_000_000; i++) {
            sum += i;
        }
        assertTrue(sum > 0, "sanity: loop must produce a positive sum");

        long end = CpuTimer.currentThreadCpuTimeNanos();
        assertTrue(end >= start,
            "CPU time must be monotonically non-decreasing: start=" + start + " end=" + end);

        long elapsed = end - start;
        assertTrue(elapsed > 1_000,
            "Expected at least 1 μs of CPU time for 1M additions, got " + elapsed + " ns");
    }

    @Test
    public void twoSuccessiveCallsAreNonDecreasing() {
        long t1 = CpuTimer.currentThreadCpuTimeNanos();
        long t2 = CpuTimer.currentThreadCpuTimeNanos();
        assertTrue(t2 >= t1,
            "Two successive calls must be non-decreasing: t1=" + t1 + " t2=" + t2);
    }
}
