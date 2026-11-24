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
import java.lang.ref.Reference;
import java.lang.ref.ReferenceQueue;
import java.lang.ref.SoftReference;
import java.lang.ref.WeakReference;
import java.lang.reflect.Member;
import java.lang.reflect.Method;
import java.lang.reflect.Modifier;
import java.nio.ByteBuffer;
import java.util.Arrays;
import java.util.HashSet;
import java.util.HexFormat;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.atomic.AtomicInteger;

/**
 * Tracks guarded byte arrays and reports out-of-bounds access detected through rewritten bytecode.
 * <p>
 * {@link ByteBuf#array()} of a pooled heap buffer returns a guard array, and array accesses in instrumented code are
 * redirected to the backing array with a bounds check against the slot of the buffer. Calls from instrumented code to
 * uninstrumented code (JDK classes, the other {@link #EXCLUDED_PACKAGES excluded packages}, and native methods) that
 * pass a byte array are rewritten to pass the backing array instead (see {@link #bootstrapCall}), after checking the
 * range that the offset and length arguments describe.
 * <p>
 * Known limits:
 * <ul>
 *     <li>Only the range at the entry into uninstrumented code is checked. When the JDK calls back into an
 *     instrumented override with the array (e.g. an inherited {@code OutputStream.write(byte[])} calling an
 *     overridden {@code write(byte[], int, int)}), the override gets the backing array without bounds. An
 *     uninstrumented method that accesses more than the range it was given is not detected either.</li>
 *     <li>Constructor calls {@code super(array, off, len)} and {@code this(...)} into an excluded superclass are not
 *     rewritten, because the receiver is uninitialized.</li>
 *     <li>At instrumentation time, a call to an instrumented owner is only rewritten when the method is native or
 *     inherited from an uninstrumented superclass. Default methods of uninstrumented interfaces, and instrumented
 *     static owners whose implementation at runtime is uninstrumented, still receive the guard array.</li>
 *     <li>Byte arrays passed as {@code Object} (e.g. to {@code Unsafe}) or inside a {@code byte[][]} (e.g.
 *     {@code Unpooled.wrappedBuffer(byte[]...)}) are not unwrapped.</li>
 *     <li>When there is only an offset or only a length, or the arguments are passed to {@code java.lang.foreign}
 *     (e.g. {@code MemorySegment.ofArray}, which zstd-jni uses on Java 22+), the backing array is passed without a
 *     range check. {@link ByteBuffer#wrap(byte[])} of a guard array is not range-checked either, because nothing is
 *     accessed yet and the position and limit may still be moved into the slot. {@link ByteBuffer#array()} of such a
 *     buffer in instrumented code returns the guard array again, but not for its slices and duplicates.</li>
 *     <li>Class files older than Java 7 cannot use invokedynamic, so their calls are not rewritten at all.</li>
 *     <li>{@code MethodHandle} and {@code VarHandle} calls are not rewritten.</li>
 * </ul>
 */
@Internal
public final class ByteBufArraySanitizer {
    /**
     * Packages that are not instrumented. When instrumented code passes a guard array to these, they receive the
     * backing array instead. Packages of JDK modules are not instrumented either.
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

    /**
     * Packages of the JDK modules that are not instrumented (defined to the boot or platform class loader).
     */
    private static final Set<String> JDK_PACKAGES = jdkPackages();

    /**
     * Shared cache of {@link #implementationUninstrumented}, per receiver class.
     */
    private static final ClassValue<Map<MethodKey, Boolean>> IMPLEMENTATIONS = new ClassValue<>() {
        @Override
        protected Map<MethodKey, Boolean> computeValue(Class<?> type) {
            return new ConcurrentHashMap<>();
        }
    };

    /**
     * Heap {@link ByteBuffer}s that wrap the backing array of a guard array, and the id of the guard array.
     */
    private static final Map<IdentityWeakKey, Integer> WRAPPED_BUFFERS = new ConcurrentHashMap<>();
    private static final ReferenceQueue<ByteBuffer> WRAPPED_BUFFERS_QUEUE = new ReferenceQueue<>();

    static {
        for (int i = 0; i < SLOTS.length; i++) {
            SLOTS[i] = new Slot();
        }
        try {
            MethodHandles.Lookup lookup = MethodHandles.lookup();
            IS_GUARD_CANDIDATE = lookup.findStatic(ByteBufArraySanitizer.class, "isGuardCandidate", MethodType.methodType(boolean.class, byte[].class));
            UNWRAP_ARGUMENTS = lookup.findStatic(ByteBufArraySanitizer.class, "unwrapArguments", MethodType.methodType(Object[].class, int[].class, Object[].class));
            RECEIVER_IMPLEMENTATION_UNINSTRUMENTED = lookup.findStatic(ByteBufArraySanitizer.class, "receiverImplementationUninstrumented", MethodType.methodType(boolean.class, MethodKey.class, Object.class));
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

        Slot slot = SLOTS[Math.floorMod(i, SLOTS.length)];
        slot.id = i;
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
        return rememberWrapped(ByteBuffer.wrap(slot.backing, off, len), slot);
    }

    public static ByteBuffer byteBufferWrap(byte[] array) {
        Slot slot = guardSlot(array);
        if (slot == null) {
            return ByteBuffer.wrap(array);
        }
        // nothing is accessed yet, and position and limit may still be moved into the slot. Accesses through the
        // JDK are not checked, but accesses through array() in instrumented code are.
        return rememberWrapped(ByteBuffer.wrap(slot.backing), slot);
    }

    public static byte[] byteBufferArray(ByteBuffer buffer) {
        byte[] array = buffer.array();
        if (WRAPPED_BUFFERS.isEmpty()) {
            return array;
        }
        Integer id = WRAPPED_BUFFERS.get(new IdentityWeakKey(buffer, null));
        if (id == null) {
            return array;
        }
        // the slot may have been reused for another buffer, or the guard array may have been collected
        Slot slot = SLOTS[Math.floorMod(id, SLOTS.length)];
        SoftReference<byte[]> ref = slot.guard;
        byte[] guard = ref == null ? null : ref.get();
        return slot.id == id && slot.backing == array && guard != null ? guard : array;
    }

    private static ByteBuffer rememberWrapped(ByteBuffer buffer, Slot slot) {
        for (Reference<?> stale; (stale = WRAPPED_BUFFERS_QUEUE.poll()) != null; ) {
            WRAPPED_BUFFERS.remove(stale);
        }
        WRAPPED_BUFFERS.put(new IdentityWeakKey(buffer, WRAPPED_BUFFERS_QUEUE), slot.id);
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
                RECEIVER_IMPLEMENTATION_UNINSTRUMENTED, 0, new MethodKey(name, type.dropParameterTypes(0, 1).changeReturnType(void.class)));
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

    private static boolean receiverImplementationUninstrumented(MethodKey method, Object receiver) {
        // with a null receiver, the original target throws the NPE
        if (receiver == null) {
            return false;
        }
        Class<?> type = receiver.getClass();
        Map<MethodKey, Boolean> cache = IMPLEMENTATIONS.get(type);
        Boolean result = cache.get(method);
        if (result == null) {
            result = implementationUninstrumented(type, method);
            cache.put(method, result);
        }
        return result;
    }

    /**
     * Check whether the implementation of a method in a receiver class is uninstrumented.
     *
     * @param type   The receiver class
     * @param method The method
     * @return Whether the implementation is uninstrumented
     */
    private static boolean implementationUninstrumented(Class<?> type, MethodKey method) {
        try {
            for (Class<?> c = type; c != null; c = c.getSuperclass()) {
                for (Method m : c.getDeclaredMethods()) {
                    if (!Modifier.isStatic(m.getModifiers()) && !Modifier.isAbstract(m.getModifiers())
                        && m.getName().equals(method.name()) && Arrays.equals(m.getParameterTypes(), method.parameterTypes().parameterArray())) {
                        return isUninstrumented(m);
                    }
                }
            }
            // default method
            return isUninstrumented(type.getMethod(method.name(), method.parameterTypes().parameterArray()));
        } catch (ReflectiveOperationException | LinkageError e) {
            // if unknown, unwrap: that is always safe
            return true;
        }
    }

    static boolean isUninstrumented(Class<?> type) {
        return UNINSTRUMENTED.get(type);
    }

    /**
     * Check whether a class is not instrumented, by name: it is in an excluded package, or in a package of a JDK
     * module. This is the same as {@link #isUninstrumented(Class)}, for classes that may not be loaded yet.
     *
     * @param name The binary name of the class
     * @return {@code true} if the class is not instrumented
     */
    static boolean isUninstrumented(String name) {
        int lastDot = name.lastIndexOf('.');
        return isExcluded(name) || (lastDot != -1 && JDK_PACKAGES.contains(name.substring(0, lastDot)));
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

    private static Set<String> jdkPackages() {
        // the transformer skips the boot class loader, and the platform class loader cannot see this class
        ClassLoader platform = ClassLoader.getPlatformClassLoader();
        Set<String> packages = new HashSet<>();
        for (Module module : ModuleLayer.boot().modules()) {
            ClassLoader loader = module.getClassLoader();
            if (loader == null || loader == platform) {
                packages.addAll(module.getPackages());
            }
        }
        return Set.copyOf(packages);
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
        /**
         * The value of {@link #NEXT} for the current guard array.
         */
        int id;
        byte[] backing;
        int start;
        int end;

        SoftReference<byte[]> guard;
    }

    /**
     * A method, for the cache of {@link #implementationUninstrumented}.
     *
     * @param name           The method name
     * @param parameterTypes The parameter types, with a {@code void} return type
     */
    private record MethodKey(String name, MethodType parameterTypes) {
    }

    /**
     * Weak reference to a {@link ByteBuffer} that compares by identity, as {@link ByteBuffer#equals} compares the
     * content.
     */
    private static final class IdentityWeakKey extends WeakReference<ByteBuffer> {
        private final int hash;

        IdentityWeakKey(ByteBuffer referent, ReferenceQueue<ByteBuffer> queue) {
            super(referent, queue);
            hash = System.identityHashCode(referent);
        }

        @Override
        public boolean equals(Object o) {
            if (this == o) {
                return true;
            }
            if (!(o instanceof IdentityWeakKey other)) {
                return false;
            }
            ByteBuffer referent = get();
            return referent != null && referent == other.get();
        }

        @Override
        public int hashCode() {
            return hash;
        }
    }
}
