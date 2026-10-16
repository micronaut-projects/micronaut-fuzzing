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
import java.util.List;
import java.util.Objects;

/**
 * Differential fuzzer for single-threaded {@link ByteBufAllocator} operation sequences.
 * <p>
 * All operation arguments are clamped to valid values, so no operation may throw. Any exception is a finding.
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
        TestState baseline = TestState.create(BASELINE_ALLOCATOR, compositeSelector, plainSelector, plainInitialCapacity);
        TestState candidate = null;
        Throwable failure = null;
        try {
            candidate = TestState.create(candidateAllocator, compositeSelector, plainSelector, plainInitialCapacity);
            compareState("initial", baseline, candidate);
            for (int i = 0; i < operations.size(); i++) {
                AllocatorOperation operation = operations.get(i);
                Integer baselineResult = operation.apply(baseline);
                Integer candidateResult = operation.apply(candidate);
                if (!Objects.equals(baselineResult, candidateResult)) {
                    throw new AssertionError("Operation " + i + " returned different results: baseline=" + baselineResult + ", candidate=" + candidateResult);
                }
                compareState("operation " + i, baseline, candidate);
            }
        } catch (Throwable t) {
            failure = t;
        }
        if (candidate != null) {
            failure = release(candidate, failure);
        }
        failure = release(baseline, failure);
        rethrow(failure);
    }

    /**
     * Release the given state. If that fails, the exception is added to the primary failure, if there is one.
     *
     * @return The primary failure
     */
    private static Throwable release(TestState state, Throwable failure) {
        try {
            state.release();
        } catch (Throwable t) {
            if (failure == null) {
                return t;
            }
            failure.addSuppressed(t);
        }
        return failure;
    }

    private static void rethrow(Throwable failure) {
        if (failure == null) {
            return;
        }
        if (failure instanceof RuntimeException e) {
            throw e;
        }
        if (failure instanceof Error e) {
            throw e;
        }
        throw new AssertionError(failure);
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
        boolean variant = provider.consumeBoolean();
        byte[] bytes = provider.consumeBytes(length);
        return new BufferOperation(selector, prefixLength, extraCapacity, bufferSelector, variant, bytes);
    }

    private static void compareState(String description, TestState baseline, TestState candidate) {
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
        compareReadableBytes(description + ": composite", baselineComposite, candidateComposite);
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
        compareReadableBytes(description + ": plain", baselinePlain, candidatePlain);
    }

    private static void compareReadableBytes(String description, ByteBuf baseline, ByteBuf candidate) {
        if (ByteBufUtil.equals(baseline, candidate)) {
            return;
        }
        int length = Math.min(baseline.readableBytes(), candidate.readableBytes());
        for (int i = 0; i < length; i++) {
            byte expected = baseline.getByte(baseline.readerIndex() + i);
            byte actual = candidate.getByte(candidate.readerIndex() + i);
            if (expected != actual) {
                throw new AssertionError(description + " readable bytes differ at offset " + i + ": baseline=" + expected + ", candidate=" + actual);
            }
        }
        throw new AssertionError(description + " readable byte count differs: baseline=" + baseline.readableBytes() + ", candidate=" + candidate.readableBytes());
    }

    private sealed interface AllocatorOperation permits AddComponentOperation, AddFlattenedComponentOperation, ReadByteOperation,
        SkipBytesOperation, DiscardReadComponentsOperation, DiscardReadBytesOperation, GetByteOperation, SetByteOperation,
        ShrinkCapacityOperation, WritePlainOperation, EnsureWritablePlainOperation, SetPlainCapacityOperation,
        SkipPlainBytesOperation, DiscardPlainReadBytesOperation {
        /**
         * Apply this operation.
         *
         * @param state The state to apply the operation to
         * @return An observable result that must be the same for both allocators, or {@code null}
         */
        Integer apply(TestState state);
    }

    /**
     * A new buffer to add to the composite.
     *
     * @param selector       Selects the component index or the split point
     * @param prefixLength   Number of bytes before the reader index of the new buffer
     * @param extraCapacity  Number of writable bytes after the content
     * @param bufferSelector Selects heap, direct or default buffer
     * @param variant        {@link AddComponentOperation}: insert at the index given by {@code selector} instead of
     *                       appending. {@link AddFlattenedComponentOperation}: wrap the buffer in a nested composite
     *                       buffer of two slices before flattening.
     * @param bytes          The readable content
     */
    private record BufferOperation(
        int selector,
        int prefixLength,
        int extraCapacity,
        int bufferSelector,
        boolean variant,
        byte[] bytes
    ) {
        ByteBuf newBuffer(ByteBufAllocator allocator) {
            int capacity = prefixLength + bytes.length + extraCapacity;
            ByteBuf buffer = switch (bufferSelector) {
                case 0 -> allocator.heapBuffer(capacity, capacity);
                case 1 -> allocator.directBuffer(capacity, capacity);
                case 2 -> allocator.buffer(capacity, capacity);
                default -> throw new AssertionError("Unexpected buffer type");
            };
            // The prefix is not readable, so its content does not matter
            buffer.setIndex(prefixLength, prefixLength);
            buffer.writeBytes(bytes);
            return buffer;
        }
    }

    private record AddComponentOperation(BufferOperation bufferOperation) implements AllocatorOperation {
        @Override
        public Integer apply(TestState state) {
            CompositeByteBuf composite = state.composite();
            if (composite.numComponents() >= MAX_COMPONENTS) {
                return null;
            }
            ByteBuf buffer = bufferOperation.newBuffer(state.allocator());
            // addComponent takes ownership of the buffer, even if it fails
            if (bufferOperation.variant() && composite.numComponents() > 0) {
                int componentIndex = Math.floorMod(bufferOperation.selector(), composite.numComponents() + 1);
                composite.addComponent(true, componentIndex, buffer);
            } else {
                composite.addComponent(true, buffer);
            }
            return null;
        }
    }

    private record AddFlattenedComponentOperation(BufferOperation bufferOperation) implements AllocatorOperation {
        @Override
        public Integer apply(TestState state) {
            if (state.composite().numComponents() >= MAX_COMPONENTS) {
                return null;
            }
            ByteBuf buffer = bufferOperation.newBuffer(state.allocator());
            if (!bufferOperation.variant() || buffer.readableBytes() < 2) {
                // addFlattenedComponents takes ownership of the buffer, even if it fails
                state.composite().addFlattenedComponents(true, buffer);
            } else {
                try {
                    addNestedFlattenedComponent(state, buffer);
                } finally {
                    // only retained slices were added
                    buffer.release();
                }
            }
            return null;
        }

        private void addNestedFlattenedComponent(TestState state, ByteBuf buffer) {
            CompositeByteBuf nested = state.allocator().compositeBuffer(2);
            try {
                int firstLength = Math.floorMod(bufferOperation.selector(), buffer.readableBytes() - 1) + 1;
                nested.addComponent(true, buffer.readRetainedSlice(firstLength));
                nested.addComponent(true, buffer.readRetainedSlice(buffer.readableBytes()));
            } catch (Throwable t) {
                nested.release();
                throw t;
            }
            // addFlattenedComponents takes ownership of the nested buffer, even if it fails
            state.composite().addFlattenedComponents(true, nested);
        }
    }

    private record ReadByteOperation() implements AllocatorOperation {
        @Override
        public Integer apply(TestState state) {
            if (!state.composite().isReadable()) {
                return null;
            }
            return (int) state.composite().readByte();
        }
    }

    private record SkipBytesOperation(int selector) implements AllocatorOperation {
        @Override
        public Integer apply(TestState state) {
            state.composite().skipBytes(Math.floorMod(selector, state.composite().readableBytes() + 1));
            return null;
        }
    }

    private record DiscardReadComponentsOperation() implements AllocatorOperation {
        @Override
        public Integer apply(TestState state) {
            state.composite().discardReadComponents();
            return null;
        }
    }

    private record DiscardReadBytesOperation() implements AllocatorOperation {
        @Override
        public Integer apply(TestState state) {
            state.composite().discardReadBytes();
            return null;
        }
    }

    private record GetByteOperation(int selector) implements AllocatorOperation {
        @Override
        public Integer apply(TestState state) {
            int readableBytes = state.composite().readableBytes();
            if (readableBytes == 0) {
                return null;
            }
            int relativeIndex = Math.floorMod(selector, readableBytes);
            return (int) state.composite().getByte(state.composite().readerIndex() + relativeIndex);
        }
    }

    private record SetByteOperation(int selector, byte value) implements AllocatorOperation {
        @Override
        public Integer apply(TestState state) {
            int readableBytes = state.composite().readableBytes();
            if (readableBytes != 0) {
                int relativeIndex = Math.floorMod(selector, readableBytes);
                state.composite().setByte(state.composite().readerIndex() + relativeIndex, value);
            }
            return null;
        }
    }

    private record ShrinkCapacityOperation(int selector) implements AllocatorOperation {
        @Override
        public Integer apply(TestState state) {
            int readableBytes = state.composite().readableBytes();
            if (readableBytes != 0) {
                int newReadableBytes = Math.floorMod(selector, readableBytes + 1);
                state.composite().capacity(state.composite().readerIndex() + newReadableBytes);
            }
            return null;
        }
    }

    private record WritePlainOperation(byte[] bytes) implements AllocatorOperation {
        @Override
        public Integer apply(TestState state) {
            if (state.plain().writerIndex() + bytes.length <= MAX_PLAIN_CAPACITY) {
                state.plain().writeBytes(bytes);
            }
            return null;
        }
    }

    private record EnsureWritablePlainOperation(int selector) implements AllocatorOperation {
        @Override
        public Integer apply(TestState state) {
            ByteBuf plain = state.plain();
            int minWritableBytes = Math.floorMod(selector, MAX_PLAIN_CAPACITY - plain.writerIndex() + 1);
            plain.ensureWritable(minWritableBytes);
            if (plain.writableBytes() < minWritableBytes) {
                throw new AssertionError("ensureWritable(" + minWritableBytes + ") left only " + plain.writableBytes() + " writable bytes");
            }
            return null;
        }
    }

    private record SetPlainCapacityOperation(int selector) implements AllocatorOperation {
        @Override
        public Integer apply(TestState state) {
            int newCapacity = Math.floorMod(selector, MAX_PLAIN_CAPACITY + 1);
            state.plain().capacity(newCapacity);
            return state.plain().capacity();
        }
    }

    private record SkipPlainBytesOperation(int selector) implements AllocatorOperation {
        @Override
        public Integer apply(TestState state) {
            state.plain().skipBytes(Math.floorMod(selector, state.plain().readableBytes() + 1));
            return null;
        }
    }

    private record DiscardPlainReadBytesOperation() implements AllocatorOperation {
        @Override
        public Integer apply(TestState state) {
            state.plain().discardReadBytes();
            return null;
        }
    }

    private record TestState(ByteBufAllocator allocator, CompositeByteBuf composite, ByteBuf plain) {
        static TestState create(ByteBufAllocator allocator, int compositeSelector, int plainSelector, int plainInitialCapacity) {
            CompositeByteBuf composite = newComposite(allocator, compositeSelector);
            try {
                return new TestState(allocator, composite, newPlain(allocator, plainSelector, plainInitialCapacity));
            } catch (Throwable t) {
                composite.release();
                throw t;
            }
        }

        void release() {
            try {
                ReferenceCountUtil.release(composite);
            } finally {
                ReferenceCountUtil.release(plain);
            }
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
