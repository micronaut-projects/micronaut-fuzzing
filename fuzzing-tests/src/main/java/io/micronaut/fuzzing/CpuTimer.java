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

import java.lang.foreign.Arena;
import java.lang.foreign.FunctionDescriptor;
import java.lang.foreign.Linker;
import java.lang.foreign.MemoryLayout;
import java.lang.foreign.MemorySegment;
import java.lang.foreign.SymbolLookup;
import java.lang.foreign.ValueLayout;

/**
 * Returns the current thread CPU time using Linux clock_gettime(CLOCK_THREAD_CPUTIME_ID)
 * via the Java Foreign Function & Memory API.
 *
 * @author AI
 */
@SuppressWarnings({"Since15", "preview"})
public final class CpuTimer {
    private CpuTimer() {
    }

    // Linux clock id for per-thread CPU time
    private static final int CLOCK_THREAD_CPUTIME_ID = 3;

    private static final long NANO_PER_SEC = 1_000_000_000L;

    // struct timespec { time_t tv_sec; long tv_nsec; }
    // On Linux x86_64 both are 8-byte longs.
    private static final MemoryLayout TIMESPEC_LAYOUT = MemoryLayout.structLayout(
        ValueLayout.JAVA_LONG.withName("tv_sec"),
        ValueLayout.JAVA_LONG.withName("tv_nsec")
    );

    private static final long OFF_TV_SEC = TIMESPEC_LAYOUT.byteOffset(MemoryLayout.PathElement.groupElement("tv_sec"));
    private static final long OFF_TV_NSEC = TIMESPEC_LAYOUT.byteOffset(MemoryLayout.PathElement.groupElement("tv_nsec"));

    private static final Linker LINKER = Linker.nativeLinker();
    private static final FunctionDescriptor FD_CLOCK_GETTIME = FunctionDescriptor.of(
        ValueLayout.JAVA_INT,       // return type: int
        ValueLayout.JAVA_INT,       // clockid_t
        ValueLayout.ADDRESS         // struct timespec*
    );

    private static final Arena LOOKUP_ARENA = Arena.ofAuto();
    private static final java.lang.invoke.MethodHandle MH_CLOCK_GETTIME;

    static {
        try {
            SymbolLookup lookup;
            try {
                // Prefer the default platform lookup if available (JDK 22+)
                lookup = LINKER.defaultLookup();
            } catch (Throwable ignore) {
                // Fallback to libc lookup
                lookup = SymbolLookup.libraryLookup("c", LOOKUP_ARENA);
            }
            MemorySegment sym = lookup.find("clock_gettime")
                .orElseGet(() -> SymbolLookup.libraryLookup("c", LOOKUP_ARENA).find("clock_gettime")
                    .orElseThrow(() -> new UnsatisfiedLinkError("clock_gettime symbol not found")));
            MH_CLOCK_GETTIME = LINKER.downcallHandle(sym, FD_CLOCK_GETTIME);
        } catch (Throwable t) {
            throw new ExceptionInInitializerError(t);
        }
    }

    /**
     * Returns the current thread CPU time in nanoseconds, obtained from
     * clock_gettime(CLOCK_THREAD_CPUTIME_ID).
     */
    public static long currentThreadCpuTimeNanos() {
        try (Arena arena = Arena.ofConfined()) {
            MemorySegment ts = arena.allocate(TIMESPEC_LAYOUT);
            int ret = (int) MH_CLOCK_GETTIME.invokeExact(CLOCK_THREAD_CPUTIME_ID, ts);
            if (ret != 0) {
                throw new IllegalStateException("clock_gettime failed with code " + ret);
            }
            long sec = ts.get(ValueLayout.JAVA_LONG, OFF_TV_SEC);
            long nsec = ts.get(ValueLayout.JAVA_LONG, OFF_TV_NSEC);
            return sec * NANO_PER_SEC + nsec;
        } catch (Throwable t) {
            throw new RuntimeException("Failed to invoke clock_gettime", t);
        }
    }
}
