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

    private static final MethodHandle BALOAD;
    private static final MethodHandle BASTORE;
    private static final MethodHandle BYTE_BUF_ARRAY;

    static {
        try {
            METHOD_BALOAD_BOOTSTRAP = SanitizerBootstrap.class.getMethod("baloadBootstrap", MethodHandles.Lookup.class, String.class, MethodType.class);
            METHOD_BASTORE_BOOTSTRAP = SanitizerBootstrap.class.getMethod("bastoreBootstrap", MethodHandles.Lookup.class, String.class, MethodType.class);
            METHOD_BYTE_BUF_ARRAY_BOOTSTRAP = SanitizerBootstrap.class.getMethod("byteBufArrayBootstrap", MethodHandles.Lookup.class, String.class, MethodType.class);

            BALOAD = MethodHandles.lookup().findStatic(ByteBufArraySanitizer.class, "baload", MethodType.methodType(byte.class, byte[].class, int.class));
            BASTORE = MethodHandles.lookup().findStatic(ByteBufArraySanitizer.class, "bastore", MethodType.methodType(void.class, byte[].class, int.class, byte.class));
            BYTE_BUF_ARRAY = MethodHandles.lookup().findStatic(ByteBufArraySanitizer.class, "byteBufArray", MethodType.methodType(byte[].class, ByteBuf.class));
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
}
