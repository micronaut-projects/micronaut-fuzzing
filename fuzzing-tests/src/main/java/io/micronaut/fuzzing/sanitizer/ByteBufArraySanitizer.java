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

import com.code_intelligence.jazzer.api.FuzzerSecurityIssueCritical;
import com.code_intelligence.jazzer.api.Jazzer;
import io.micronaut.core.annotation.Internal;
import io.netty.buffer.ByteBuf;

import java.lang.invoke.CallSite;
import java.lang.invoke.ConstantCallSite;
import java.lang.invoke.MethodHandle;
import java.lang.invoke.MethodHandles;
import java.lang.invoke.MethodType;
import java.lang.ref.SoftReference;
import java.lang.ref.WeakReference;
import java.lang.reflect.Member;
import java.lang.reflect.Method;
import java.lang.reflect.Modifier;
import java.nio.ByteBuffer;
import java.util.Arrays;
import java.util.HexFormat;
import java.util.List;
import java.util.concurrent.atomic.AtomicInteger;

/**
 * Tracks guarded byte arrays and reports out-of-bounds access detected through rewritten bytecode.
 */
@Internal
public final class ByteBufArraySanitizer {
    /**
     * Packages that are not instrumented. When instrumented code passes a guard array to these, they receive the
     * backing array instead.
     */
    static final List<String> EXCLUDED_PACKAGES = List.of(
        "com.code_intelligence",
        "com.sun",
        "net.bytebuddy",
        "sun",
        "java",
        "jdk",
        "io.netty.buffer" // need to ignore nested calls to .array
    );

    static final int KIND_VIRTUAL = 182;
    static final int KIND_SPECIAL = 183;
    static final int KIND_STATIC = 184;
    static final int KIND_INTERFACE = 185;
    static final int KIND_NEW = 187;

    private static final AtomicInteger NEXT = new AtomicInteger();
    private static final Slot[] SLOTS = new Slot[256];

    private static final byte PATTERN_B1 = (byte) 0xd1;

    /**
     * The array is accessed as a whole.
     */
    private static final int WHOLE = 0;
    /**
     * The array is accessed from an offset, for a length.
     */
    private static final int OFF_LEN = 1;
    /**
     * The array is accessed from an inclusive start index to an exclusive end index.
     */
    private static final int FROM_TO = 2;
    /**
     * The accessed range is unknown.
     */
    private static final int UNCHECKED = 3;
    private static final int PLAN_STRIDE = 4;

    private static final MethodHandle IS_GUARD_CANDIDATE;
    private static final MethodHandle UNWRAP_ARGUMENTS;
    private static final MethodHandle RECEIVER_IMPLEMENTATION_UNINSTRUMENTED;

    private static final ClassValue<Boolean> UNINSTRUMENTED = new ClassValue<>() {
        @Override
        protected Boolean computeValue(Class<?> type) {
            ClassLoader loader = type.getClassLoader();
            if (loader == null || isExcluded(type.getName())) {
                return true;
            }
            try {
                // same condition as SanitizerTransformer
                Class.forName(ByteBufArraySanitizer.class.getName(), false, loader);
                return false;
            } catch (ClassNotFoundException | LinkageError e) {
                return true;
            }
        }
    };

    @SuppressWarnings("unchecked")
    private static final WeakReference<ByteBuffer>[] WRAPPED_BUFFERS = new WeakReference[64];
    private static final byte[][] WRAPPED_GUARDS = new byte[WRAPPED_BUFFERS.length][];
    private static volatile int wrappedCount;

    static {
        for (int i = 0; i < SLOTS.length; i++) {
            SLOTS[i] = new Slot();
        }
        try {
            MethodHandles.Lookup lookup = MethodHandles.lookup();
            IS_GUARD_CANDIDATE = lookup.findStatic(ByteBufArraySanitizer.class, "isGuardCandidate", MethodType.methodType(boolean.class, byte[].class));
            UNWRAP_ARGUMENTS = lookup.findStatic(ByteBufArraySanitizer.class, "unwrapArguments", MethodType.methodType(Object[].class, int[].class, Object[].class));
            RECEIVER_IMPLEMENTATION_UNINSTRUMENTED = lookup.findStatic(ByteBufArraySanitizer.class, "receiverImplementationUninstrumented", MethodType.methodType(boolean.class, ClassValue.class, Object.class));
        } catch (ReflectiveOperationException e) {
            throw new ExceptionInInitializerError(e);
        }
    }

    public static byte baload(byte[] array, int index) {
        if (array[0] == PATTERN_B1) {
            array = checkIndexSlow(array, index);
        }
        return array[index];
    }

    public static void bastore(byte[] array, int index, byte value) {
        if (array[0] == PATTERN_B1) {
            array = checkIndexSlow(array, index);
        }
        array[index] = value;
    }

    private static byte[] checkIndexSlow(byte[] array, int index) {
        Slot slot = findSlot(array);
        if (slot != null) {
            if (index < slot.start || index >= slot.end) {
                Jazzer.reportFindingFromHook(new FuzzerSecurityIssueCritical("Out-of-bounds array access"));
            }
            return slot.backing;
        } else {
            return array;
        }
    }

    private static Slot findSlot(byte[] guard) {
        if (guard[0] != PATTERN_B1 || guard.length < 2) {
            return null;
        }
        Slot slot = SLOTS[guard[1] & 0xff];
        SoftReference<byte[]> ref = slot.guard;
        if (ref == null || ref.get() != guard) {
            return null;
        }
        return slot;
    }

    public static byte[] byteBufArray(ByteBuf buf) {
        byte[] array = buf.array();
        int capacity = buf.capacity();
        if (capacity == array.length) {
            return array;
        }
        int offset = buf.arrayOffset();

        Slot existing = findSlot(array);
        if (existing != null) {
            if (existing.start == offset && existing.end == offset + capacity) {
                return array;
            }
            throw new UnsupportedOperationException("Nested .array?");
        }

        byte[] guard = new byte[array.length];
        guard[0] = PATTERN_B1;

        int i = NEXT.getAndIncrement();
        guard[1] = (byte) i;

        Slot slot = SLOTS[i % SLOTS.length];
        slot.backing = array;
        slot.guard = new SoftReference<>(guard);
        slot.start = offset;
        slot.end = offset + capacity;

        return guard;
    }

    public static byte[] arraysCopyOf(byte[] array, int newLength) {
        if (array.length > 0 && array[0] == PATTERN_B1) {
            array = checkRangeSlow(array, 0, newLength);
        }
        return Arrays.copyOf(array, newLength);
    }

    public static byte[] arraysCopyOfRange(byte[] array, int from, int to) {
        if (array.length > 0 && array[0] == PATTERN_B1) {
            array = checkRangeSlow(array, from, to - from);
        }
        return Arrays.copyOfRange(array, from, to);
    }

    public static void systemArraycopy(Object src, int srcPos, Object dest, int destPos, int length) {
        if (length != 0) {
            if (src instanceof byte[] s && s[0] == PATTERN_B1) {
                src = checkRangeSlow(s, srcPos, length);
            }
            if (dest instanceof byte[] d && d[0] == PATTERN_B1) {
                dest = checkRangeSlow(d, destPos, length);
            }
        }
        System.arraycopy(src, srcPos, dest, destPos, length);
    }

    // ByteBuffer.wrap is redirected so that the JDK reads and writes the backing array through a heap ByteBuffer
    // around a guard array, while ByteBuffer.array() in instrumented code still returns the guard array.

    public static ByteBuffer byteBufferWrap(byte[] array, int off, int len) {
        Slot slot = guardSlot(array);
        if (slot == null) {
            return ByteBuffer.wrap(array, off, len);
        }
        checkRange(slot, off, len);
        return rememberWrapped(ByteBuffer.wrap(slot.backing, off, len), array);
    }

    public static ByteBuffer byteBufferWrap(byte[] array) {
        Slot slot = guardSlot(array);
        if (slot == null) {
            return ByteBuffer.wrap(array);
        }
        // nothing is accessed yet, and position and limit may still be moved into the slot. Accesses through the
        // JDK are not checked, but accesses through array() in instrumented code are.
        return rememberWrapped(ByteBuffer.wrap(slot.backing), array);
    }

    public static byte[] byteBufferArray(ByteBuffer buffer) {
        byte[] array = buffer.array();
        if (wrappedCount == 0) {
            return array;
        }
        synchronized (WRAPPED_BUFFERS) {
            for (int i = 0; i < WRAPPED_BUFFERS.length; i++) {
                WeakReference<ByteBuffer> ref = WRAPPED_BUFFERS[i];
                if (ref != null && ref.get() == buffer) {
                    byte[] guard = WRAPPED_GUARDS[i];
                    Slot slot = findSlot(guard);
                    return slot != null && slot.backing == array ? guard : array;
                }
            }
        }
        return array;
    }

    private static ByteBuffer rememberWrapped(ByteBuffer buffer, byte[] guard) {
        synchronized (WRAPPED_BUFFERS) {
            int i = wrappedCount % WRAPPED_BUFFERS.length;
            wrappedCount = i + 1;
            WRAPPED_BUFFERS[i] = new WeakReference<>(buffer);
            WRAPPED_GUARDS[i] = guard;
        }
        return buffer;
    }

    // Calls from instrumented code to uninstrumented code (methods of excluded classes, and native methods) that
    // pass a byte array are replaced with an invokedynamic that links to bootstrapCall. If an argument is a guard
    // array, the range that the other arguments describe is checked against the slot of the buffer, and the backing
    // array is passed instead.

    /**
     * Bootstrap method for a call from instrumented code that passes a byte array to uninstrumented code.
     *
     * @param lookup The lookup of the caller
     * @param name   The name of the method ({@code init} for a constructor)
     * @param type   The type of the call site: the receiver (if any) and the parameters of the original call, and its
     *               return type (the constructed type for a constructor)
     * @param kind   The original instruction, one of the {@code KIND_*} constants
     * @param owner  The owner of the original call
     * @return The call site
     * @throws ReflectiveOperationException If the method cannot be resolved
     */
    public static CallSite bootstrapCall(MethodHandles.Lookup lookup, String name, MethodType type, int kind, Class<?> owner) throws ReflectiveOperationException {
        MethodHandle target = switch (kind) {
            case KIND_STATIC -> lookup.findStatic(owner, name, type);
            case KIND_VIRTUAL, KIND_INTERFACE -> lookup.findVirtual(owner, name, type.dropParameterTypes(0, 1));
            case KIND_SPECIAL -> lookup.findSpecial(owner, name, type.dropParameterTypes(0, 1), lookup.lookupClass());
            case KIND_NEW -> lookup.findConstructor(owner, type.changeReturnType(void.class));
            default -> throw new IllegalArgumentException("Unknown kind " + kind);
        };
        Member member = reflect(lookup, target);
        target = target.asType(type);

        boolean dynamicReceiver = (kind == KIND_VIRTUAL || kind == KIND_INTERFACE)
            && (member == null || !(Modifier.isFinal(member.getModifiers()) || Modifier.isPrivate(member.getModifiers()) || Modifier.isFinal(member.getDeclaringClass().getModifiers())));
        if (!dynamicReceiver && !isUninstrumented(member)) {
            return new ConstantCallSite(target);
        }

        int[] plan = plan(owner, kind, type);
        if (plan.length == 0) {
            return new ConstantCallSite(target);
        }
        int n = type.parameterCount();
        MethodHandle unwrapping = MethodHandles.filterArguments(
                target.asSpreader(Object[].class, n),
                0,
                MethodHandles.insertArguments(UNWRAP_ARGUMENTS, 0, (Object) plan))
            .asCollector(Object[].class, n)
            .asType(type);
        if (dynamicReceiver) {
            // the static owner is uninstrumented, but the receiver may override the method in instrumented code,
            // which should see the guard array
            MethodHandle test = MethodHandles.insertArguments(
                RECEIVER_IMPLEMENTATION_UNINSTRUMENTED, 0, new ImplementationCache(name, type.dropParameterTypes(0, 1).parameterArray()));
            test = test.asType(test.type().changeParameterType(0, type.parameterType(0)));
            test = MethodHandles.dropArguments(test, 1, type.parameterList().subList(1, n));
            unwrapping = MethodHandles.guardWithTest(test, unwrapping, target);
        }
        // fast path: only take the slow path when one of the arrays may be a guard array
        MethodHandle result = target;
        for (int i = 0; i < plan.length; i += PLAN_STRIDE) {
            int index = plan[i];
            MethodHandle test = MethodHandles.dropArguments(IS_GUARD_CANDIDATE, 0, type.parameterList().subList(0, index));
            test = MethodHandles.dropArguments(test, index + 1, type.parameterList().subList(index + 1, n));
            result = MethodHandles.guardWithTest(test, unwrapping, result);
        }
        return new ConstantCallSite(result);
    }

    private static Member reflect(MethodHandles.Lookup lookup, MethodHandle target) {
        try {
            return lookup.revealDirect(target).reflectAs(Member.class, lookup);
        } catch (RuntimeException e) {
            return null;
        }
    }

    private static boolean isUninstrumented(Member member) {
        // if unknown, unwrap: that is always safe
        return member == null || isUninstrumented(member.getDeclaringClass()) || Modifier.isNative(member.getModifiers());
    }

    /**
     * Compute how to unwrap the byte array parameters. For each one, the plan contains the parameter index, the range
     * mode, and the indices of the parameters that describe the range.
     *
     * @param owner The owner of the method
     * @param kind  The kind of call
     * @param type  The type of the call site
     * @return The plan
     */
    private static int[] plan(Class<?> owner, int kind, MethodType type) {
        List<Class<?>> params = type.parameterList();
        int first = kind == KIND_STATIC || kind == KIND_NEW ? 0 : 1;
        List<Class<?>> declared = params.subList(first, params.size());
        int[] plan = new int[0];
        for (int i = first; i < params.size(); i++) {
            if (params.get(i) != byte[].class) {
                continue;
            }
            int mode;
            int a = -1;
            int b = -1;
            if (owner.getPackageName().equals("java.lang.foreign")) {
                // MemorySegment.ofArray creates a view of the whole array, that is sliced afterwards (e.g. by
                // zstd-jni on Java 22+). Reporting the whole array would be a false positive.
                mode = UNCHECKED;
            } else if (owner == String.class && kind == KIND_NEW && declared.equals(List.of(byte[].class, int.class, int.class, int.class))) {
                // String(byte[] ascii, int hibyte, int offset, int count)
                mode = OFF_LEN;
                a = first + 2;
                b = first + 3;
            } else if (owner == String.class && kind == KIND_NEW && declared.equals(List.of(byte[].class, int.class))) {
                // String(byte[] ascii, int hibyte)
                mode = WHOLE;
            } else {
                // the first two ints after the array, before the next array, are its offset and length
                int j = i + 1;
                while (j < params.size() && params.get(j) != int.class && !params.get(j).isArray()) {
                    j++;
                }
                if (j + 1 < params.size() && params.get(j) == int.class && params.get(j + 1) == int.class) {
                    mode = owner == Arrays.class || owner == HexFormat.class ? FROM_TO : OFF_LEN;
                    a = j;
                    b = j + 1;
                } else if (j < params.size() && params.get(j) == int.class) {
                    // only an offset or a length
                    mode = UNCHECKED;
                } else {
                    mode = WHOLE;
                }
            }
            plan = Arrays.copyOf(plan, plan.length + PLAN_STRIDE);
            plan[plan.length - 4] = i;
            plan[plan.length - 3] = mode;
            plan[plan.length - 2] = a;
            plan[plan.length - 1] = b;
        }
        return plan;
    }

    private static boolean isGuardCandidate(byte[] array) {
        return array != null && array.length > 1 && array[0] == PATTERN_B1;
    }

    private static Object[] unwrapArguments(int[] plan, Object[] args) {
        for (int i = 0; i < plan.length; i += PLAN_STRIDE) {
            int index = plan[i];
            Slot slot = guardSlot((byte[]) args[index]);
            if (slot == null) {
                continue;
            }
            switch (plan[i + 1]) {
                case OFF_LEN -> checkRange(slot, (int) args[plan[i + 2]], (int) args[plan[i + 3]]);
                case FROM_TO -> {
                    int from = (int) args[plan[i + 2]];
                    checkRange(slot, from, (int) args[plan[i + 3]] - from);
                }
                case WHOLE -> checkRange(slot, 0, slot.backing.length);
                default -> {
                    // UNCHECKED
                }
            }
            args[index] = slot.backing;
        }
        return args;
    }

    private static boolean receiverImplementationUninstrumented(ClassValue<Boolean> cache, Object receiver) {
        // with a null receiver, the original target throws the NPE
        return receiver != null && cache.get(receiver.getClass());
    }

    static boolean isUninstrumented(Class<?> type) {
        return UNINSTRUMENTED.get(type);
    }

    /**
     * Check whether a class is excluded from instrumentation by name.
     *
     * @param name The binary name of the class
     * @return {@code true} if the class is excluded
     */
    static boolean isExcluded(String name) {
        if (name.startsWith(ByteBufArraySanitizer.class.getName())) {
            // including nested classes
            return true;
        }
        for (String excludedPackage : EXCLUDED_PACKAGES) {
            if (name.startsWith(excludedPackage) && name.length() > excludedPackage.length() && name.charAt(excludedPackage.length()) == '.') {
                return true;
            }
        }
        return false;
    }

    private static Slot guardSlot(byte[] array) {
        return isGuardCandidate(array) ? findSlot(array) : null;
    }

    private static void checkRange(Slot slot, int off, int len) {
        if (len > 0 && (off < slot.start || (long) off + (long) len > slot.end)) {
            Jazzer.reportFindingFromHook(new FuzzerSecurityIssueCritical("Out-of-bounds array access"));
        }
    }

    private static byte[] checkRangeSlow(byte[] array, int pos, int len) {
        if (len <= 0) {
            return array;
        }
        Slot slot = findSlot(array);
        if (slot != null) {
            checkRange(slot, pos, len);
            return slot.backing;
        } else {
            return array;
        }
    }

    private static final class Slot {
        byte[] backing;
        int start;
        int end;

        SoftReference<byte[]> guard;
    }

    /**
     * Whether the implementation of a method in a receiver class is uninstrumented.
     */
    private static final class ImplementationCache extends ClassValue<Boolean> {
        private final String name;
        private final Class<?>[] parameterTypes;

        ImplementationCache(String name, Class<?>[] parameterTypes) {
            this.name = name;
            this.parameterTypes = parameterTypes;
        }

        @Override
        protected Boolean computeValue(Class<?> type) {
            try {
                for (Class<?> c = type; c != null; c = c.getSuperclass()) {
                    for (Method method : c.getDeclaredMethods()) {
                        if (!Modifier.isStatic(method.getModifiers()) && !Modifier.isAbstract(method.getModifiers())
                            && method.getName().equals(name) && Arrays.equals(method.getParameterTypes(), parameterTypes)) {
                            return isUninstrumented(method);
                        }
                    }
                }
                // default method
                return isUninstrumented(type.getMethod(name, parameterTypes));
            } catch (ReflectiveOperationException | LinkageError e) {
                // if unknown, unwrap: that is always safe
                return true;
            }
        }
    }
}
