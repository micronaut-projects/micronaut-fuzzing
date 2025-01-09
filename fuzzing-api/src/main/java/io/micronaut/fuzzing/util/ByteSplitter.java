/*
 * Copyright 2017-2025 original authors
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
package io.micronaut.fuzzing.util;

import io.micronaut.core.annotation.NonNull;

import java.nio.charset.StandardCharsets;
import java.util.Arrays;
import java.util.Iterator;

/**
 * Utility class for splitting input bytes into pieces along a pre-defined separator.
 */
public final class ByteSplitter {
    private final byte[] separator;

    private ByteSplitter(byte[] separator) {
        this.separator = separator;
    }

    /**
     * Create a new splitter.
     *
     * @param separator The separator, will be UTF-8 decoded
     * @return The splitter
     */
    @NonNull
    public static ByteSplitter create(@NonNull String separator) {
        return create(separator.getBytes(StandardCharsets.UTF_8));
    }

    /**
     * Create a new splitter.
     *
     * @param separator The separator
     * @return The splitter
     */
    @NonNull
    public static ByteSplitter create(byte @NonNull [] separator) {
        return new ByteSplitter(separator);
    }

    /**
     * Split the given input. Convenience method that delegates to {@link #splitIterator(byte[])}.
     *
     * @param input The input to split
     * @return An iterable that iterates over the pieces
     */
    @NonNull
    public Iterable<byte[]> split(@NonNull byte[] input) {
        return () -> splitIterator(input);
    }

    /**
     * Split the given input.
     *
     * @param input The input to split
     * @return An iterator for the pieces
     */
    @NonNull
    public ChunkIterator splitIterator(@NonNull byte[] input) {
        return new ChunkIterator(input);
    }

    /**
     * Iterator for the split pieces.
     */
    public class ChunkIterator implements Iterator<byte[]> {
        private final byte[] input;

        private int index = -1;
        private int end = -separator.length;

        private ChunkIterator(byte[] input) {
            this.input = input;
        }

        private void findEnd() {
            for (int i = index; i < input.length - separator.length + 1; i++) {
                boolean match = true;
                for (int j = 0; j < separator.length; j++) {
                    if (input[i + j] != separator[j]) {
                        match = false;
                        break;
                    }
                }
                if (match) {
                    end = i;
                    return;
                }
            }
            end = input.length;
        }

        /**
         * @return Whether there is another piece after the current one.
         */
        @Override
        public boolean hasNext() {
            return end < input.length;
        }

        /**
         * Proceed to the next piece. This behaves like {@link #next()}, except it doesn't return
         * the data array.
         *
         * @throws IllegalStateException if we reached end of input ({@link #hasNext()} returns
         * {@code false})
         */
        public void proceed() {
            index = end + separator.length;
            if (index > input.length) {
                throw new IllegalStateException("No more bytes left");
            }
            findEnd();
        }

        /**
         * Get the current piece as a byte array.
         *
         * @return Copy of the current piece
         * @throws IllegalStateException if {@link #proceed()} hasn't been called yet
         */
        public byte[] asByteArray() {
            if (index < 0) {
                throw new IllegalStateException("Please call proceed() first");
            }
            return Arrays.copyOfRange(input, index, end);
        }

        /**
         * Get the current piece as a string (UTF-8 decoded).
         *
         * @return Copy of the current piece
         * @throws IllegalStateException if {@link #proceed()} hasn't been called yet
         */
        public String asString() {
            if (index < 0) {
                throw new IllegalStateException("Please call proceed() first");
            }
            return new String(input, index, end - index, StandardCharsets.UTF_8);
        }

        /**
         * Get the start index of the current piece in the input array.
         *
         * @return The start index
         * @throws IllegalStateException if {@link #proceed()} hasn't been called yet
         */
        public int start() {
            if (index < 0) {
                throw new IllegalStateException("Please call proceed() first");
            }
            return index;
        }

        /**
         * Get the length of the current piece in the input array.
         *
         * @return The length
         * @throws IllegalStateException if {@link #proceed()} hasn't been called yet
         */
        public int length() {
            if (index < 0) {
                throw new IllegalStateException("Please call proceed() first");
            }
            return end - index;
        }

        /**
         * Proceed to the next piece and return it. Equivalent to
         * {@code proceed(); return asByteArray();}.
         *
         * @return The next piece
         */
        @Override
        public byte @NonNull [] next() {
            proceed();
            return asByteArray();
        }
    }
}
