package io.micronaut.fuzzing.sanitizer;

import io.netty.buffer.ByteBuf;

import java.lang.invoke.CallSite;
import java.lang.invoke.ConstantCallSite;
import java.lang.invoke.MethodHandle;
import java.lang.invoke.MethodHandles;
import java.lang.invoke.MethodType;
import java.lang.reflect.Method;

public class SanitizerBootstrap {
    static final Method METHOD_BALOAD_BOOTSTRAP;
    static final Method METHOD_BASTORE_BOOTSTRAP;
    static final Method METHOD_BYTE_BUF_ARRAY_BOOTSTRAP;
    static final Method METHOD_ARRAYS_COPY_OF_BOOTSTRAP;
    static final Method METHOD_ARRAYS_COPY_OF_RANGE_BOOTSTRAP;
    static final Method METHOD_SYSTEM_ARRAYCOPY_BOOTSTRAP;

    private static final MethodHandle BALOAD;
    private static final MethodHandle BASTORE;
    private static final MethodHandle BYTE_BUF_ARRAY;
    private static final MethodHandle ARRAYS_COPY_OF;
    private static final MethodHandle ARRAYS_COPY_OF_RANGE;
    private static final MethodHandle SYSTEM_ARRAYCOPY;

    static {
        try {
            METHOD_BALOAD_BOOTSTRAP = SanitizerBootstrap.class.getMethod("baloadBootstrap", MethodHandles.Lookup.class, String.class, MethodType.class);
            METHOD_BASTORE_BOOTSTRAP = SanitizerBootstrap.class.getMethod("bastoreBootstrap", MethodHandles.Lookup.class, String.class, MethodType.class);
            METHOD_BYTE_BUF_ARRAY_BOOTSTRAP = SanitizerBootstrap.class.getMethod("byteBufArrayBootstrap", MethodHandles.Lookup.class, String.class, MethodType.class);
            METHOD_ARRAYS_COPY_OF_BOOTSTRAP = SanitizerBootstrap.class.getMethod("arraysCopyOfBootstrap", MethodHandles.Lookup.class, String.class, MethodType.class);
            METHOD_ARRAYS_COPY_OF_RANGE_BOOTSTRAP = SanitizerBootstrap.class.getMethod("arraysCopyOfRangeBootstrap", MethodHandles.Lookup.class, String.class, MethodType.class);
            METHOD_SYSTEM_ARRAYCOPY_BOOTSTRAP = SanitizerBootstrap.class.getMethod("systemArraycopyBootstrap", MethodHandles.Lookup.class, String.class, MethodType.class);

            BALOAD = MethodHandles.lookup().findStatic(ByteBufArraySanitizer.class, "baload", MethodType.methodType(byte.class, byte[].class, int.class));
            BASTORE = MethodHandles.lookup().findStatic(ByteBufArraySanitizer.class, "bastore", MethodType.methodType(void.class, byte[].class, int.class, byte.class));
            BYTE_BUF_ARRAY = MethodHandles.lookup().findStatic(ByteBufArraySanitizer.class, "byteBufArray", MethodType.methodType(byte[].class, ByteBuf.class));
            ARRAYS_COPY_OF = MethodHandles.lookup().findStatic(ByteBufArraySanitizer.class, "arraysCopyOf", MethodType.methodType(byte[].class, byte[].class, int.class));
            ARRAYS_COPY_OF_RANGE = MethodHandles.lookup().findStatic(ByteBufArraySanitizer.class, "arraysCopyOfRange", MethodType.methodType(byte[].class, byte[].class, int.class, int.class));
            SYSTEM_ARRAYCOPY = MethodHandles.lookup().findStatic(ByteBufArraySanitizer.class, "systemArraycopy", MethodType.methodType(void.class, Object.class, int.class, Object.class, int.class, int.class));
        } catch (NoSuchMethodException | IllegalAccessException e) {
            throw new RuntimeException(e);
        }
    }

    @SuppressWarnings("unused")
    public static CallSite baloadBootstrap(MethodHandles.Lookup lookup, String name, MethodType type) {
        return new ConstantCallSite(BALOAD);
    }

    @SuppressWarnings("unused")
    public static CallSite bastoreBootstrap(MethodHandles.Lookup lookup, String name, MethodType type) {
        return new ConstantCallSite(BASTORE);
    }

    @SuppressWarnings("unused")
    public static CallSite byteBufArrayBootstrap(MethodHandles.Lookup lookup, String name, MethodType type) {
        return new ConstantCallSite(BYTE_BUF_ARRAY);
    }

    @SuppressWarnings("unused")
    public static CallSite arraysCopyOfBootstrap(MethodHandles.Lookup lookup, String name, MethodType type) {
        return new ConstantCallSite(ARRAYS_COPY_OF);
    }

    @SuppressWarnings("unused")
    public static CallSite arraysCopyOfRangeBootstrap(MethodHandles.Lookup lookup, String name, MethodType type) {
        return new ConstantCallSite(ARRAYS_COPY_OF_RANGE);
    }

    @SuppressWarnings("unused")
    public static CallSite systemArraycopyBootstrap(MethodHandles.Lookup lookup, String name, MethodType type) {
        // Adapt the generic (Object,int,Object,int,int) handle to the call site's exact signature
        return new ConstantCallSite(SYSTEM_ARRAYCOPY.asType(type));
    }
}
