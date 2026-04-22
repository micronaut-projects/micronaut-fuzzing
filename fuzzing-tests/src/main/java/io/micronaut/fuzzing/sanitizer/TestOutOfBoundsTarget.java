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

import java.util.Arrays;

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

    public static void main(String[] args) {
        if (args.length == 1) {
            runScenario(args[0]);
            return;
        }
        LocalJazzerRunner.create(TestOutOfBoundsTarget.class).fuzz();
    }

    private static void runScenario(String scenario) {
        switch (scenario) {
            case "aload" -> runAload();
            case "copyOf" -> runCopyOf();
            case "copyOfRange" -> runCopyOfRange();
            case "arraycopySource" -> runArraycopySource();
            case "arraycopyDest" -> runArraycopyDest();
            default -> throw new IllegalArgumentException("Unknown scenario: " + scenario);
        }
    }

    private static void runAload() {
        ByteBuf buffer = ByteBufAllocator.DEFAULT.heapBuffer(16);
        try {
            if (buffer.arrayOffset() == 0) {
                sink = buffer.array()[16];
            } else {
                sink = buffer.array()[0];
            }
        } finally {
            buffer.release();
        }
    }

    private static void runCopyOf() {
        ByteBuf parent = ByteBufAllocator.DEFAULT.heapBuffer(32);
        ByteBuf buffer = parent.retainedSlice(8, 16);
        try {
            Arrays.copyOf(buffer.array(), 1);
        } finally {
            buffer.release();
            parent.release();
        }
    }

    private static void runCopyOfRange() {
        ByteBuf parent = ByteBufAllocator.DEFAULT.heapBuffer(32);
        ByteBuf buffer = parent.retainedSlice(8, 16);
        try {
            Arrays.copyOfRange(buffer.array(), 0, 1);
        } finally {
            buffer.release();
            parent.release();
        }
    }

    private static void runArraycopySource() {
        ByteBuf parent = ByteBufAllocator.DEFAULT.heapBuffer(32);
        ByteBuf buffer = parent.retainedSlice(8, 16);
        byte[] dest = new byte[1];
        try {
            System.arraycopy(buffer.array(), 0, dest, 0, 1);
        } finally {
            buffer.release();
            parent.release();
        }
    }

    private static void runArraycopyDest() {
        ByteBuf parent = ByteBufAllocator.DEFAULT.heapBuffer(32);
        ByteBuf buffer = parent.retainedSlice(8, 16);
        byte[] src = new byte[1];
        try {
            System.arraycopy(src, 0, buffer.array(), 0, 1);
        } finally {
            buffer.release();
            parent.release();
        }
    }
}
