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

import jdk.jfr.Enabled;
import jdk.jfr.Event;
import jdk.jfr.Name;
import jdk.jfr.StackTrace;

/**
 * Per-input CPU budget of the fuzz targets. The budget is
 * {@code CPU_TIME_FACTOR * (baseCpuTime + inputSize * inputCpuTime + outputSize * outputCpuTime + exceptionCpuTime)}
 * nanoseconds of thread CPU time (see {@link CpuTimer}). Every measurement is also recorded as a
 * JFR event, which {@code cpu-times.jfc} enables, to tune the budget parameters.
 */
public final class CpuBudget {
    /**
     * Factor between the budget parameters and nanoseconds.
     */
    public static final long CPU_TIME_FACTOR = 1024;
    /**
     * Default fixed budget per input, about 0.5s.
     */
    public static final long DEFAULT_BASE_CPU_TIME = 500000;

    private CpuBudget() {
    }

    /**
     * Records a measurement and checks it against the budget.
     *
     * @param actualTime       The measured CPU time in nanoseconds
     * @param baseCpuTime      The fixed budget
     * @param inputCpuTime     The budget per input byte
     * @param outputCpuTime    The budget per output byte
     * @param exceptionCpuTime The additional budget if an exception was handled
     * @param inputSize        The input size
     * @param outputSize       The output size
     * @param handledException Whether an exception was handled
     * @throws CpuLimitException if the measurement exceeds the budget
     */
    public static void check(long actualTime, long baseCpuTime, long inputCpuTime, long outputCpuTime, long exceptionCpuTime,
                             int inputSize, long outputSize, boolean handledException) {
        long cpuTimeBudget = baseCpuTime + inputSize * inputCpuTime + outputSize * outputCpuTime;
        if (handledException) {
            cpuTimeBudget += exceptionCpuTime;
        }

        CpuTimeSample sample = new CpuTimeSample();
        if (sample.isEnabled()) {
            sample.factor = CPU_TIME_FACTOR;
            sample.baseCpuTime = baseCpuTime;
            sample.inputCpuTime = inputCpuTime;
            sample.outputCpuTime = outputCpuTime;
            sample.exceptionCpuTime = exceptionCpuTime;
            sample.inputSize = inputSize;
            sample.outputSize = outputSize;
            sample.handledException = handledException;
            sample.actualTime = actualTime;
            sample.commit();
        }

        if (actualTime > CPU_TIME_FACTOR * cpuTimeBudget) {
            throw new CpuLimitException("CPU limit triggered. in=" + inputSize + " out=" + outputSize + " actual=" + actualTime);
        }
    }

    /**
     * Runs an action and checks its CPU time against a budget that only depends on the input
     * size. A slow first run can be caused by class loading or JIT compilation, so the action is
     * retried once before the input is reported. The action must not depend on state left behind
     * by a previous run.
     *
     * @param inputSize    The input size
     * @param baseCpuTime  The fixed budget
     * @param inputCpuTime The budget per input byte
     * @param action       The action
     */
    public static void runWithRetry(int inputSize, long baseCpuTime, long inputCpuTime, Runnable action) {
        try {
            runOnce(inputSize, baseCpuTime, inputCpuTime, action);
        } catch (CpuLimitException e) {
            runOnce(inputSize, baseCpuTime, inputCpuTime, action);
        }
    }

    private static void runOnce(int inputSize, long baseCpuTime, long inputCpuTime, Runnable action) {
        long start = CpuTimer.currentThreadCpuTimeNanos();
        action.run();
        long actualTime = CpuTimer.currentThreadCpuTimeNanos() - start;
        check(actualTime, baseCpuTime, inputCpuTime, 0, 0, inputSize, 0, false);
    }

    /**
     * Thrown when an input exceeds its CPU budget.
     */
    public static final class CpuLimitException extends RuntimeException {
        CpuLimitException(String message) {
            super(message);
        }
    }

    /**
     * JFR event for one measurement. The name is kept from the time this event was part of
     * {@link EmbeddedChannelFuzzerBase}, for existing recordings and {@code cpu-times.jfc}.
     */
    @Name("io.micronaut.fuzzing.EmbeddedChannelFuzzerBase$CpuTimeSample")
    @Enabled(false)
    @StackTrace(false)
    static final class CpuTimeSample extends Event {
        long factor;
        long baseCpuTime;
        long inputCpuTime;
        long outputCpuTime;
        long exceptionCpuTime;
        int inputSize;
        long outputSize;
        boolean handledException;
        long actualTime;
    }
}
