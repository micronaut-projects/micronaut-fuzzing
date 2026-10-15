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

import com.code_intelligence.jazzer.api.CannedFuzzedDataProvider;
import com.code_intelligence.jazzer.api.FuzzedDataProvider;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

/**
 * Builds canned inputs for {@link ByteBufAllocatorFuzzerBase}, in the order the fuzzer consumes them.
 */
final class AllocatorFuzzerInput {
    static final int HEAP = 0;
    static final int DIRECT = 1;
    static final int DEFAULT = 2;

    private final List<Object> values = new ArrayList<>();

    AllocatorFuzzerInput(int compositeType, int plainType, int plainInitialCapacity) {
        values.add(compositeType);
        values.add(plainType);
        values.add(plainInitialCapacity);
    }

    private AllocatorFuzzerInput operation(int operation, Object... arguments) {
        // remainingBytes() check of the operation loop
        values.add(Integer.MAX_VALUE);
        values.add(operation);
        values.addAll(Arrays.asList(arguments));
        return this;
    }

    AllocatorFuzzerInput addComponent(int selector, int prefixLength, int extraCapacity, int bufferType, boolean insert, byte[] bytes) {
        return operation(0, selector, prefixLength, bytes.length, extraCapacity, bufferType, insert, bytes);
    }

    AllocatorFuzzerInput addFlattenedComponent(int selector, int prefixLength, int extraCapacity, int bufferType, boolean nested, byte[] bytes) {
        return operation(1, selector, prefixLength, bytes.length, extraCapacity, bufferType, nested, bytes);
    }

    AllocatorFuzzerInput readByte() {
        return operation(2);
    }

    AllocatorFuzzerInput skipBytes(int selector) {
        return operation(3, selector);
    }

    AllocatorFuzzerInput discardReadComponents() {
        return operation(4);
    }

    AllocatorFuzzerInput discardReadBytes() {
        return operation(5);
    }

    AllocatorFuzzerInput getByte(int selector) {
        return operation(6, selector);
    }

    AllocatorFuzzerInput setByte(int selector, byte value) {
        return operation(7, selector, value);
    }

    AllocatorFuzzerInput shrinkCapacity(int selector) {
        return operation(8, selector);
    }

    AllocatorFuzzerInput writePlain(byte[] bytes) {
        return operation(9, bytes.length, bytes);
    }

    AllocatorFuzzerInput ensureWritablePlain(int selector) {
        return operation(10, selector);
    }

    AllocatorFuzzerInput setPlainCapacity(int selector) {
        return operation(11, selector);
    }

    AllocatorFuzzerInput skipPlainBytes(int selector) {
        return operation(12, selector);
    }

    AllocatorFuzzerInput discardPlainReadBytes() {
        return operation(13);
    }

    FuzzedDataProvider build() {
        List<Object> result = new ArrayList<>(values);
        // end of the operation loop
        result.add(0);
        return CannedFuzzedDataProvider.create(result);
    }

    static byte[] bytes(int length) {
        byte[] bytes = new byte[length];
        for (int i = 0; i < length; i++) {
            bytes[i] = (byte) (i * 31 + 7);
        }
        return bytes;
    }
}
