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

import com.code_intelligence.jazzer.api.FuzzedDataProvider;
import io.netty.util.internal.InternalThreadLocalMap;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;

import static io.netty.buffer.AllocatorFuzzerInput.DEFAULT;
import static io.netty.buffer.AllocatorFuzzerInput.DIRECT;
import static io.netty.buffer.AllocatorFuzzerInput.HEAP;
import static io.netty.buffer.AllocatorFuzzerInput.bytes;
import static org.junit.jupiter.api.Assertions.assertTrue;

abstract class AbstractAllocatorFuzzerTest {
    abstract void fuzz(FuzzedDataProvider provider);

    @ParameterizedTest
    @ValueSource(ints = {HEAP, DIRECT, DEFAULT})
    void compositeOperations(int compositeType) {
        fuzz(new AllocatorFuzzerInput(compositeType, HEAP, 0)
            .addComponent(3, 2, 5, HEAP, false, bytes(20))
            .addComponent(-7, 0, 0, DIRECT, true, bytes(300))
            .addComponent(1, 1, 1, DEFAULT, true, bytes(9000))
            .readByte()
            .skipBytes(15)
            .getByte(-12345)
            .setByte(42, (byte) 0x55)
            .discardReadComponents()
            .addFlattenedComponent(0, 4, 0, DIRECT, false, bytes(100))
            .skipBytes(400)
            .discardReadBytes()
            .shrinkCapacity(1000)
            .readByte()
            .build());
    }

    @ParameterizedTest
    @ValueSource(ints = {HEAP, DIRECT, DEFAULT})
    void nestedFlattenedComponent(int bufferType) {
        fuzz(new AllocatorFuzzerInput(DEFAULT, HEAP, 0)
            .addComponent(0, 0, 0, HEAP, false, bytes(4))
            .addFlattenedComponent(5, 3, 10, bufferType, true, bytes(64))
            .getByte(17)
            .skipBytes(30)
            .discardReadComponents()
            .build());
    }

    @ParameterizedTest
    @ValueSource(ints = {HEAP, DIRECT, DEFAULT})
    void plainBufferGrowth(int plainType) {
        fuzz(new AllocatorFuzzerInput(HEAP, plainType, 16)
            .writePlain(bytes(100))
            .ensureWritablePlain(70000)
            .skipPlainBytes(30)
            .setPlainCapacity(50)
            .writePlain(bytes(5000))
            .discardPlainReadBytes()
            .setPlainCapacity(200000)
            .writePlain(bytes(65536))
            .skipPlainBytes(-1)
            .setPlainCapacity(10)
            .setPlainCapacity(0)
            .writePlain(bytes(3))
            .build());
    }

    @Test
    void manyInputsDoNotRegisterThreadLocals() {
        int before = InternalThreadLocalMap.lastVariableIndex();
        for (int i = 0; i < 200; i++) {
            fuzz(new AllocatorFuzzerInput(i % 3, (i + 1) % 3, i)
                .addComponent(i, 1, 0, i % 3, false, bytes(i * 37 % 1000))
                .writePlain(bytes(i * 101 % 20000))
                .build());
        }
        // A new allocator per input would register new FastThreadLocals (thread caches) every time
        assertTrue(InternalThreadLocalMap.lastVariableIndex() - before < 10,
            "FastThreadLocal count grew from " + before + " to " + InternalThreadLocalMap.lastVariableIndex());
    }
}
