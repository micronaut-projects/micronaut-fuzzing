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
import io.micronaut.fuzzing.FlagAppender;
import io.netty.util.LeakPresenceDetector;
import io.netty.util.ReferenceCountUtil;
import io.netty.util.concurrent.FastThreadLocalThread;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

/**
 * Differential fuzzer for single-threaded {@link ByteBufAllocator} operation sequences.
 */
abstract class ByteBufAllocatorFuzzerBase {
    private static final ByteBufAllocator BASELINE_ALLOCATOR = new UnpooledByteBufAllocator(false);
    private static final int MAX_COMPONENTS = 32;
    private static final int MAX_OPERATIONS = 64;
    private static final int MIN_OPERATION_BYTES = 8;
    private static final int MAX_BUFFER_SIZE = 65536;
    private static final int DEFAULT_MAX_COMPONENTS = 64;
    private static final int MAX_INITIAL_PLAIN_CAPACITY = 4096;
    private static final int MAX_PLAIN_CAPACITY = 1 << 20;

    private final ByteBufAllocator candidateAllocator;

    ByteBufAllocatorFuzzerBase(ByteBufAllocator candidateAllocator) {
        this.candidateAllocator = candidateAllocator;
    }

    final void test(FuzzedDataProvider provider) {
        int compositeSelector = provider.consumeInt(0, 2);
        int plainSelector = provider.consumeInt(0, 2);
        int plainInitialCapacity = provider.consumeInt(0, MAX_INITIAL_PLAIN_CAPACITY);
        List<AllocatorOperation> operations = createOperations(provider);
        // Run on a FastThreadLocal-enabled thread so that the thread-local caches of the candidate allocator are
        // used. They are freed again when runWithFastThreadLocal returns.
        FastThreadLocalThread.runWithFastThreadLocal(() -> run(compositeSelector, plainSelector, plainInitialCapacity, operations));
        LeakPresenceDetector.check();
        FlagAppender.checkTriggered();
    }

    private void run(int compositeSelector, int plainSelector, int plainInitialCapacity, List<AllocatorOperation> operations) {
        TestState baseline = new TestState(BASELINE_ALLOCATOR, compositeSelector, plainSelector, plainInitialCapacity);
        try {
            TestState candidate = new TestState(candidateAllocator, compositeSelector, plainSelector, plainInitialCapacity);
            try {
                compareState("initial", baseline, candidate);
                for (int i = 0; i < operations.size(); i++) {
                    AllocatorOperation operation = operations.get(i);
                    OperationResult baselineResult = apply(operation, baseline);
                    OperationResult candidateResult = apply(operation, candidate);
                    if (!baselineResult.equals(candidateResult)) {
                        throw new AssertionError("Operation " + i + " returned different results: baseline=" + baselineResult + ", candidate=" + candidateResult);
                    }
                    if (!baselineResult.hasException()) {
                        compareState("operation " + i, baseline, candidate);
                    }
                }
            } finally {
                candidate.release();
            }
        } finally {
            baseline.release();
        }
    }

    private List<AllocatorOperation> createOperations(FuzzedDataProvider provider) {
        List<AllocatorOperation> operations = new ArrayList<>();
        while (operations.size() < MAX_OPERATIONS && provider.remainingBytes() >= MIN_OPERATION_BYTES) {
            operations.add(createOperation(provider));
        }
        return operations;
    }

    private AllocatorOperation createOperation(FuzzedDataProvider provider) {
        return switch (provider.consumeInt(0, 13)) {
            case 0 -> new AddComponentOperation(readBufferOperation(provider));
            case 1 -> new AddFlattenedComponentOperation(readBufferOperation(provider));
            case 2 -> new ReadByteOperation();
            case 3 -> new SkipBytesOperation(provider.consumeInt());
            case 4 -> new DiscardReadComponentsOperation();
            case 5 -> new DiscardReadBytesOperation();
            case 6 -> new GetByteOperation(provider.consumeInt());
            case 7 -> new SetByteOperation(provider.consumeInt(), provider.consumeByte());
            case 8 -> new ShrinkCapacityOperation(provider.consumeInt());
            case 9 -> new WritePlainOperation(provider.consumeBytes(provider.consumeInt(0, MAX_BUFFER_SIZE)));
            case 10 -> new EnsureWritablePlainOperation(provider.consumeInt());
            case 11 -> new SetPlainCapacityOperation(provider.consumeInt());
            case 12 -> new SkipPlainBytesOperation(provider.consumeInt());
            case 13 -> new DiscardPlainReadBytesOperation();
            default -> throw new AssertionError("Unexpected operation");
        };
    }

    private BufferOperation readBufferOperation(FuzzedDataProvider provider) {
        int selector = provider.consumeInt();
        int prefixLength = provider.consumeInt(0, MAX_BUFFER_SIZE);
        int length = provider.consumeInt(0, MAX_BUFFER_SIZE);
        int extraCapacity = provider.consumeInt(0, 1024);
        int bufferSelector = provider.consumeInt(0, 2);
        boolean firstFlag = provider.consumeBoolean();
        byte[] bytes = provider.consumeBytes(length);
        return new BufferOperation(selector, prefixLength, extraCapacity, bufferSelector, firstFlag, bytes);
    }

    private OperationResult apply(AllocatorOperation operation, TestState state) {
        try {
            return operation.apply(state);
        } catch (IndexOutOfBoundsException e) {
            return OperationResult.exception(IndexOutOfBoundsException.class);
        } catch (IllegalArgumentException e) {
            return OperationResult.exception(IllegalArgumentException.class);
        }
    }

    private void compareState(String description, TestState baseline, TestState candidate) {
        CompositeByteBuf baselineComposite = baseline.composite();
        CompositeByteBuf candidateComposite = candidate.composite();
        if (baselineComposite.readerIndex() != candidateComposite.readerIndex()) {
            throw new AssertionError(description + ": readerIndex differs: baseline=" + baselineComposite.readerIndex() + ", candidate=" + candidateComposite.readerIndex());
        }
        if (baselineComposite.writerIndex() != candidateComposite.writerIndex()) {
            throw new AssertionError(description + ": writerIndex differs: baseline=" + baselineComposite.writerIndex() + ", candidate=" + candidateComposite.writerIndex());
        }
        if (baselineComposite.capacity() != candidateComposite.capacity()) {
            throw new AssertionError(description + ": capacity differs: baseline=" + baselineComposite.capacity() + ", candidate=" + candidateComposite.capacity());
        }
        if (baselineComposite.numComponents() != candidateComposite.numComponents()) {
            throw new AssertionError(description + ": component count differs: baseline=" + baselineComposite.numComponents() + ", candidate=" + candidateComposite.numComponents());
        }
        byte[] baselineBytes = readableBytes(baselineComposite);
        byte[] candidateBytes = readableBytes(candidateComposite);
        if (!Arrays.equals(baselineBytes, candidateBytes)) {
            throw new AssertionError(description + ": readable bytes differ");
        }
        // The capacity of a plain buffer is not compared: after a write, it depends on the growth policy of the
        // allocator.
        ByteBuf baselinePlain = baseline.plain();
        ByteBuf candidatePlain = candidate.plain();
        if (baselinePlain.readerIndex() != candidatePlain.readerIndex()) {
            throw new AssertionError(description + ": plain readerIndex differs: baseline=" + baselinePlain.readerIndex() + ", candidate=" + candidatePlain.readerIndex());
        }
        if (baselinePlain.writerIndex() != candidatePlain.writerIndex()) {
            throw new AssertionError(description + ": plain writerIndex differs: baseline=" + baselinePlain.writerIndex() + ", candidate=" + candidatePlain.writerIndex());
        }
        if (baselinePlain.maxCapacity() != candidatePlain.maxCapacity()) {
            throw new AssertionError(description + ": plain maxCapacity differs: baseline=" + baselinePlain.maxCapacity() + ", candidate=" + candidatePlain.maxCapacity());
        }
        if (candidatePlain.capacity() < candidatePlain.writerIndex() || candidatePlain.capacity() > candidatePlain.maxCapacity()) {
            throw new AssertionError(description + ": plain capacity " + candidatePlain.capacity() + " out of bounds");
        }
        if (!Arrays.equals(readableBytes(baselinePlain), readableBytes(candidatePlain))) {
            throw new AssertionError(description + ": plain readable bytes differ");
        }
    }

    private byte[] readableBytes(ByteBuf buffer) {
        byte[] bytes = new byte[buffer.readableBytes()];
        buffer.getBytes(buffer.readerIndex(), bytes);
        return bytes;
    }

    private static int positiveModulo(int value, int divisor) {
        return Math.floorMod(value, divisor);
    }

    private sealed interface AllocatorOperation permits AddComponentOperation, AddFlattenedComponentOperation, ReadByteOperation,
        SkipBytesOperation, DiscardReadComponentsOperation, DiscardReadBytesOperation, GetByteOperation, SetByteOperation,
        ShrinkCapacityOperation, WritePlainOperation, EnsureWritablePlainOperation, SetPlainCapacityOperation,
        SkipPlainBytesOperation, DiscardPlainReadBytesOperation {
        OperationResult apply(TestState state);
    }

    private record BufferOperation(
        int selector,
        int prefixLength,
        int extraCapacity,
        int bufferSelector,
        boolean insert,
        byte[] bytes
    ) {
        ByteBuf newBuffer(ByteBufAllocator allocator) {
            int capacity = prefixLength + bytes.length + extraCapacity;
            return switch (bufferSelector) {
                case 0 -> allocator.heapBuffer(capacity, capacity);
                case 1 -> allocator.directBuffer(capacity, capacity);
                case 2 -> allocator.buffer(capacity, capacity);
                default -> throw new AssertionError("Unexpected buffer type");
            };
        }

        void write(ByteBuf buffer) {
            for (int i = 0; i < prefixLength; i++) {
                buffer.writeByte(selector + i);
            }
            buffer.skipBytes(prefixLength);
            buffer.writeBytes(bytes);
        }
    }

    private record AddComponentOperation(BufferOperation bufferOperation) implements AllocatorOperation {
        @Override
        public OperationResult apply(TestState state) {
            if (state.composite().numComponents() >= MAX_COMPONENTS) {
                return OperationResult.noValue();
            }
            ByteBuf buffer = bufferOperation.newBuffer(state.allocator());
            try {
                bufferOperation.write(buffer);
                if (bufferOperation.insert() && state.composite().numComponents() > 0) {
                    int componentIndex = positiveModulo(bufferOperation.selector(), state.composite().numComponents() + 1);
                    state.composite().addComponent(true, componentIndex, buffer);
                } else {
                    state.composite().addComponent(true, buffer);
                }
                buffer = null;
                return OperationResult.noValue();
            } finally {
                ReferenceCountUtil.release(buffer);
            }
        }
    }

    private record AddFlattenedComponentOperation(BufferOperation bufferOperation) implements AllocatorOperation {
        @Override
        public OperationResult apply(TestState state) {
            if (state.composite().numComponents() >= MAX_COMPONENTS) {
                return OperationResult.noValue();
            }
            ByteBuf buffer = bufferOperation.newBuffer(state.allocator());
            try {
                bufferOperation.write(buffer);
                if (!bufferOperation.insert() || buffer.readableBytes() < 2) {
                    state.composite().addFlattenedComponents(true, buffer);
                    buffer = null;
                } else {
                    // This only adds retained slices, so the buffer itself is still released below.
                    addNestedFlattenedComponent(state, buffer);
                }
                return OperationResult.noValue();
            } finally {
                ReferenceCountUtil.release(buffer);
            }
        }

        private void addNestedFlattenedComponent(TestState state, ByteBuf buffer) {
            CompositeByteBuf nested = state.allocator().compositeBuffer(2);
            try {
                int firstLength = positiveModulo(bufferOperation.selector(), buffer.readableBytes() - 1) + 1;
                nested.addComponent(true, buffer.readRetainedSlice(firstLength));
                nested.addComponent(true, buffer.readRetainedSlice(buffer.readableBytes()));
                state.composite().addFlattenedComponents(true, nested);
                nested = null;
            } finally {
                ReferenceCountUtil.release(nested);
            }
        }
    }

    private record ReadByteOperation() implements AllocatorOperation {
        @Override
        public OperationResult apply(TestState state) {
            if (!state.composite().isReadable()) {
                return OperationResult.noValue();
            }
            return OperationResult.byteValue(state.composite().readByte());
        }
    }

    private record SkipBytesOperation(int selector) implements AllocatorOperation {
        @Override
        public OperationResult apply(TestState state) {
            int readableBytes = state.composite().readableBytes();
            if (readableBytes != 0) {
                state.composite().skipBytes(positiveModulo(selector, readableBytes + 1));
            }
            return OperationResult.noValue();
        }
    }

    private record DiscardReadComponentsOperation() implements AllocatorOperation {
        @Override
        public OperationResult apply(TestState state) {
            state.composite().discardReadComponents();
            return OperationResult.noValue();
        }
    }

    private record DiscardReadBytesOperation() implements AllocatorOperation {
        @Override
        public OperationResult apply(TestState state) {
            state.composite().discardReadBytes();
            return OperationResult.noValue();
        }
    }

    private record GetByteOperation(int selector) implements AllocatorOperation {
        @Override
        public OperationResult apply(TestState state) {
            int readableBytes = state.composite().readableBytes();
            if (readableBytes == 0) {
                return OperationResult.noValue();
            }
            int relativeIndex = positiveModulo(selector, readableBytes);
            return OperationResult.byteValue(state.composite().getByte(state.composite().readerIndex() + relativeIndex));
        }
    }

    private record SetByteOperation(int selector, byte value) implements AllocatorOperation {
        @Override
        public OperationResult apply(TestState state) {
            int readableBytes = state.composite().readableBytes();
            if (readableBytes != 0) {
                int relativeIndex = positiveModulo(selector, readableBytes);
                state.composite().setByte(state.composite().readerIndex() + relativeIndex, value);
            }
            return OperationResult.noValue();
        }
    }

    private record ShrinkCapacityOperation(int selector) implements AllocatorOperation {
        @Override
        public OperationResult apply(TestState state) {
            int readableBytes = state.composite().readableBytes();
            if (readableBytes != 0) {
                int newReadableBytes = positiveModulo(selector, readableBytes + 1);
                state.composite().capacity(state.composite().readerIndex() + newReadableBytes);
            }
            return OperationResult.noValue();
        }
    }

    private record WritePlainOperation(byte[] bytes) implements AllocatorOperation {
        @Override
        public OperationResult apply(TestState state) {
            if (state.plain().writerIndex() + bytes.length <= MAX_PLAIN_CAPACITY) {
                state.plain().writeBytes(bytes);
            }
            return OperationResult.noValue();
        }
    }

    private record EnsureWritablePlainOperation(int selector) implements AllocatorOperation {
        @Override
        public OperationResult apply(TestState state) {
            ByteBuf plain = state.plain();
            int minWritableBytes = positiveModulo(selector, MAX_PLAIN_CAPACITY - plain.writerIndex() + 1);
            plain.ensureWritable(minWritableBytes);
            if (plain.writableBytes() < minWritableBytes) {
                throw new AssertionError("ensureWritable(" + minWritableBytes + ") left only " + plain.writableBytes() + " writable bytes");
            }
            return OperationResult.noValue();
        }
    }

    private record SetPlainCapacityOperation(int selector) implements AllocatorOperation {
        @Override
        public OperationResult apply(TestState state) {
            int newCapacity = positiveModulo(selector, MAX_PLAIN_CAPACITY + 1);
            state.plain().capacity(newCapacity);
            return OperationResult.intValue(state.plain().capacity());
        }
    }

    private record SkipPlainBytesOperation(int selector) implements AllocatorOperation {
        @Override
        public OperationResult apply(TestState state) {
            state.plain().skipBytes(positiveModulo(selector, state.plain().readableBytes() + 1));
            return OperationResult.noValue();
        }
    }

    private record DiscardPlainReadBytesOperation() implements AllocatorOperation {
        @Override
        public OperationResult apply(TestState state) {
            state.plain().discardReadBytes();
            return OperationResult.noValue();
        }
    }

    private record OperationResult(Class<? extends RuntimeException> exceptionType, Integer value) {
        boolean hasException() {
            return exceptionType != null;
        }

        static OperationResult noValue() {
            return new OperationResult(null, null);
        }

        static OperationResult byteValue(byte value) {
            return new OperationResult(null, (int) value);
        }

        static OperationResult intValue(int value) {
            return new OperationResult(null, value);
        }

        static OperationResult exception(Class<? extends RuntimeException> exceptionType) {
            return new OperationResult(exceptionType, null);
        }
    }

    private record TestState(ByteBufAllocator allocator, CompositeByteBuf composite, ByteBuf plain) {
        TestState(ByteBufAllocator allocator, int compositeSelector, int plainSelector, int plainInitialCapacity) {
            this(allocator, newComposite(allocator, compositeSelector), newPlain(allocator, plainSelector, plainInitialCapacity));
        }

        void release() {
            ReferenceCountUtil.release(composite);
            ReferenceCountUtil.release(plain);
        }

        private static ByteBuf newPlain(ByteBufAllocator allocator, int plainSelector, int initialCapacity) {
            return switch (plainSelector) {
                case 0 -> allocator.heapBuffer(initialCapacity, MAX_PLAIN_CAPACITY);
                case 1 -> allocator.directBuffer(initialCapacity, MAX_PLAIN_CAPACITY);
                case 2 -> allocator.buffer(initialCapacity, MAX_PLAIN_CAPACITY);
                default -> throw new AssertionError("Unexpected plain buffer type");
            };
        }

        private static CompositeByteBuf newComposite(ByteBufAllocator allocator, int compositeSelector) {
            return switch (compositeSelector) {
                case 0 -> allocator.compositeHeapBuffer(DEFAULT_MAX_COMPONENTS);
                case 1 -> allocator.compositeDirectBuffer(DEFAULT_MAX_COMPONENTS);
                case 2 -> allocator.compositeBuffer(DEFAULT_MAX_COMPONENTS);
                default -> throw new AssertionError("Unexpected composite buffer type");
            };
        }
    }
}
