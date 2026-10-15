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

import io.netty.buffer.ByteBuf;
import net.bytebuddy.asm.AsmVisitorWrapper;
import net.bytebuddy.description.field.FieldDescription;
import net.bytebuddy.description.field.FieldList;
import net.bytebuddy.description.method.MethodDescription;
import net.bytebuddy.description.method.MethodList;
import net.bytebuddy.description.type.TypeDefinition;
import net.bytebuddy.description.type.TypeDescription;
import net.bytebuddy.implementation.Implementation;
import net.bytebuddy.jar.asm.ClassVisitor;
import net.bytebuddy.jar.asm.FieldVisitor;
import net.bytebuddy.jar.asm.Handle;
import net.bytebuddy.jar.asm.Label;
import net.bytebuddy.jar.asm.MethodVisitor;
import net.bytebuddy.jar.asm.Opcodes;
import net.bytebuddy.jar.asm.Type;
import net.bytebuddy.matcher.ElementMatchers;
import net.bytebuddy.pool.TypePool;

import java.lang.invoke.MethodHandles;
import java.lang.invoke.MethodType;
import java.lang.reflect.Method;
import java.nio.ByteBuffer;
import java.util.ArrayDeque;
import java.util.Arrays;
import java.util.Deque;

/**
 * ASM visitor wrapper that redirects selected byte-array operations to sanitizer helpers.
 */
final class VisitorWrapperImpl extends AsmVisitorWrapper.AbstractBase {
    private static final String BOOLEAN_ARRAY = "[Z";
    private static final String BYTE_ARRAY = "[B";

    private static final Method BALOAD;
    private static final Method BASTORE;
    private static final Method BYTE_BUF_ARRAY;
    private static final Method ARRAYS_COPY_OF;
    private static final Method ARRAYS_COPY_OF_RANGE;
    private static final Method SYSTEM_ARRAYCOPY;
    private static final Method BYTE_BUFFER_WRAP;
    private static final Method BYTE_BUFFER_WRAP_RANGE;
    private static final Method BYTE_BUFFER_ARRAY;
    private static final Handle BOOTSTRAP_CALL;
    /**
     * Placeholder on the stack of pending {@code NEW} instructions for one that is not followed by {@code DUP}.
     */
    private static final String NEW_WITHOUT_DUP = "";

    static {
        try {
            BALOAD = ByteBufArraySanitizer.class.getMethod("baload", byte[].class, int.class);
            BASTORE = ByteBufArraySanitizer.class.getMethod("bastore", byte[].class, int.class, byte.class);
            BYTE_BUF_ARRAY = ByteBufArraySanitizer.class.getMethod("byteBufArray", ByteBuf.class);
            ARRAYS_COPY_OF = ByteBufArraySanitizer.class.getMethod("arraysCopyOf", byte[].class, int.class);
            ARRAYS_COPY_OF_RANGE = ByteBufArraySanitizer.class.getMethod("arraysCopyOfRange", byte[].class, int.class, int.class);
            SYSTEM_ARRAYCOPY = ByteBufArraySanitizer.class.getMethod("systemArraycopy", Object.class, int.class, Object.class, int.class, int.class);
            BYTE_BUFFER_WRAP = ByteBufArraySanitizer.class.getMethod("byteBufferWrap", byte[].class);
            BYTE_BUFFER_WRAP_RANGE = ByteBufArraySanitizer.class.getMethod("byteBufferWrap", byte[].class, int.class, int.class);
            BYTE_BUFFER_ARRAY = ByteBufArraySanitizer.class.getMethod("byteBufferArray", ByteBuffer.class);
            Method bootstrap = ByteBufArraySanitizer.class.getMethod("bootstrapCall", MethodHandles.Lookup.class, String.class, MethodType.class, int.class, Class.class);
            BOOTSTRAP_CALL = new Handle(
                Opcodes.H_INVOKESTATIC,
                Type.getInternalName(ByteBufArraySanitizer.class),
                bootstrap.getName(),
                Type.getMethodDescriptor(bootstrap),
                false
            );
        } catch (NoSuchMethodException e) {
            throw new RuntimeException(e);
        }
        if (ByteBufArraySanitizer.KIND_VIRTUAL != Opcodes.INVOKEVIRTUAL
            || ByteBufArraySanitizer.KIND_SPECIAL != Opcodes.INVOKESPECIAL
            || ByteBufArraySanitizer.KIND_STATIC != Opcodes.INVOKESTATIC
            || ByteBufArraySanitizer.KIND_INTERFACE != Opcodes.INVOKEINTERFACE
            || ByteBufArraySanitizer.KIND_NEW != Opcodes.NEW) {
            throw new AssertionError();
        }
    }

    @Override
    public ClassVisitor wrap(TypeDescription typeDescription, ClassVisitor classVisitor, Implementation.Context context, TypePool typePool, FieldList<FieldDescription.InDefinedShape> fieldList, MethodList<?> methodList, int i, int i1) {
        return new ClassVisitorImpl(Opcodes.ASM9, classVisitor, typePool);
    }

    /**
     * Check whether a method call passes a byte array to uninstrumented code: a method of a class in an excluded
     * package or a JDK module, or a native method.
     *
     * @param typePool The type pool to resolve the owner with
     * @param owner    The internal name of the owner
     * @param name     The method name
     * @param desc     The method descriptor
     * @return Whether to redirect the call through {@link ByteBufArraySanitizer#bootstrapCall}
     */
    static boolean passesByteArrayToUninstrumented(TypePool typePool, String owner, String name, String desc) {
        if (owner.startsWith("[") || owner.startsWith("java/lang/invoke/")) {
            // array methods; signature-polymorphic MethodHandle and VarHandle methods
            return false;
        }
        boolean byteArrayParameter = false;
        for (Type argumentType : Type.getArgumentTypes(desc)) {
            if (argumentType.getDescriptor().equals(BYTE_ARRAY)) {
                byteArrayParameter = true;
                break;
            }
        }
        if (!byteArrayParameter) {
            return false;
        }
        if (ByteBufArraySanitizer.isUninstrumented(Type.getObjectType(owner).getClassName())) {
            return !Type.getObjectType(owner).getClassName().startsWith(ByteBufArraySanitizer.class.getName());
        }
        if (name.equals("<init>") || typePool == null) {
            return false;
        }
        // an instrumented owner: look for an inherited method of an excluded class, or a native method
        try {
            TypePool.Resolution resolution = typePool.describe(Type.getObjectType(owner).getClassName());
            if (!resolution.isResolved()) {
                return false;
            }
            TypeDefinition type = resolution.resolve();
            while (type != null) {
                TypeDescription erasure = type.asErasure();
                MethodList<MethodDescription.InDefinedShape> methods = erasure.getDeclaredMethods()
                    .filter(ElementMatchers.hasMethodName(name).and(ElementMatchers.hasDescriptor(desc)));
                if (!methods.isEmpty()) {
                    return methods.getOnly().isNative() || ByteBufArraySanitizer.isUninstrumented(erasure.getName());
                }
                type = erasure.getSuperClass();
            }
        } catch (RuntimeException | LinkageError e) {
            // cannot resolve: leave the call alone
        }
        return false;
    }

    private static final class ClassVisitorImpl extends ClassVisitor {
        private final TypePool typePool;
        private boolean hasBooleanArrayField;
        private boolean supportsInvokeDynamic;

        ClassVisitorImpl(int api, ClassVisitor classVisitor, TypePool typePool) {
            super(api, classVisitor);
            this.typePool = typePool;
        }

        @Override
        public FieldVisitor visitField(int access, String name, String descriptor, String signature, Object value) {
            if (BOOLEAN_ARRAY.equals(descriptor)) {
                hasBooleanArrayField = true;
            }
            return super.visitField(access, name, descriptor, signature, value);
        }

        @Override
        public void visit(int version, int access, String name, String signature, String superName, String[] interfaces) {
            supportsInvokeDynamic = (version & 0xFFFF) >= Opcodes.V1_7;
            super.visit(version, access, name, signature, superName, interfaces);
        }

        @Override
        public MethodVisitor visitMethod(int access, String name, String descriptor, String signature, String[] exceptions) {
            MethodVisitorImpl methodVisitor = new MethodVisitorImpl(Opcodes.ASM9, super.visitMethod(access, name, descriptor, signature, exceptions), supportsInvokeDynamic ? typePool : null);
            if (descriptor.contains(BOOLEAN_ARRAY)) {
                methodVisitor.ohNoBooleanArray = true;
            }
            if ("<clinit>".equals(name) && hasBooleanArrayField) {
                methodVisitor.ohNoBooleanArray = true;
            }
            return methodVisitor;
        }
    }

    private static final class MethodVisitorImpl extends MethodVisitor {
        boolean ohNoBooleanArray;

        /**
         * The type pool, or {@code null} if the class file does not support invokedynamic.
         */
        private final TypePool typePool;
        /**
         * The types of the pending {@code NEW} instructions, innermost first, or {@link #NEW_WITHOUT_DUP}.
         */
        private final Deque<String> pendingNew = new ArrayDeque<>();
        /**
         * The type of a {@code NEW} instruction that was just visited.
         */
        private String lastNew;

        MethodVisitorImpl(int api, MethodVisitor methodVisitor, TypePool typePool) {
            super(api, methodVisitor);
            this.typePool = typePool;
        }

        /**
         * Called before any instruction other than {@code DUP}, to record that the last {@code NEW} was not followed
         * by {@code DUP}.
         */
        private void notDup() {
            if (lastNew != null) {
                pendingNew.push(NEW_WITHOUT_DUP);
                lastNew = null;
            }
        }

        @Override
        public void visitTypeInsn(int opcode, String type) {
            notDup();
            if (opcode == Opcodes.NEW) {
                lastNew = type;
            }
            super.visitTypeInsn(opcode, type);
        }

        @Override
        public void visitFieldInsn(int opcode, String owner, String name, String descriptor) {
            notDup();
            if (!ohNoBooleanArray && BOOLEAN_ARRAY.equals(descriptor)) {
                ohNoBooleanArray = true;
            }
            super.visitFieldInsn(opcode, owner, name, descriptor);
        }

        @Override
        public void visitIntInsn(int opcode, int operand) {
            notDup();
            if (!ohNoBooleanArray && opcode == Opcodes.NEWARRAY && operand == Opcodes.T_BOOLEAN) {
                ohNoBooleanArray = true;
            }
            super.visitIntInsn(opcode, operand);
        }

        @Override
        public void visitVarInsn(int opcode, int varIndex) {
            notDup();
            super.visitVarInsn(opcode, varIndex);
        }

        @Override
        public void visitInvokeDynamicInsn(String name, String descriptor, Handle bootstrapMethodHandle, Object... bootstrapMethodArguments) {
            notDup();
            super.visitInvokeDynamicInsn(name, descriptor, bootstrapMethodHandle, bootstrapMethodArguments);
        }

        @Override
        public void visitJumpInsn(int opcode, Label label) {
            notDup();
            super.visitJumpInsn(opcode, label);
        }

        @Override
        public void visitLdcInsn(Object value) {
            notDup();
            super.visitLdcInsn(value);
        }

        @Override
        public void visitIincInsn(int varIndex, int increment) {
            notDup();
            super.visitIincInsn(varIndex, increment);
        }

        @Override
        public void visitTableSwitchInsn(int min, int max, Label dflt, Label... labels) {
            notDup();
            super.visitTableSwitchInsn(min, max, dflt, labels);
        }

        @Override
        public void visitLookupSwitchInsn(Label dflt, int[] keys, Label[] labels) {
            notDup();
            super.visitLookupSwitchInsn(dflt, keys, labels);
        }

        @Override
        public void visitMultiANewArrayInsn(String descriptor, int numDimensions) {
            notDup();
            super.visitMultiANewArrayInsn(descriptor, numDimensions);
        }

        @Override
        public void visitFrame(int type, int numLocal, Object[] local, int numStack, Object[] stack) {
            for (Object o : local) {
                if (BOOLEAN_ARRAY.equals(o)) {
                    ohNoBooleanArray = true;
                    break;
                }
            }
            for (Object o : stack) {
                if (BOOLEAN_ARRAY.equals(o)) {
                    ohNoBooleanArray = true;
                    break;
                }
            }

            super.visitFrame(type, numLocal, local, numStack, stack);
        }

        @Override
        public void visitInsn(int opcode) {
            if (lastNew != null) {
                pendingNew.push(opcode == Opcodes.DUP ? lastNew : NEW_WITHOUT_DUP);
                lastNew = null;
            }

            if (ohNoBooleanArray) {
                super.visitInsn(opcode);
                return;
            }

            if (opcode == Opcodes.BALOAD) {
                invokeStatic(BALOAD);
            } else if (opcode == Opcodes.BASTORE) {
                invokeStatic(BASTORE);
            } else {
                super.visitInsn(opcode);
            }
        }

        @Override
        public void visitMethodInsn(int opcode, String owner, String name, String descriptor, boolean isInterface) {
            notDup();
            // Also treat any method that mentions boolean[] in its signature (parameters or return)
            // as an escape hatch source. This covers synthetic accessors returning [Z from outer classes.
            if (!ohNoBooleanArray && descriptor.contains(BOOLEAN_ARRAY)) {
                ohNoBooleanArray = true;
            }
            String arraysOwner = Type.getInternalName(Arrays.class);
            String systemOwner = Type.getInternalName(System.class);
            String byteBufferOwner = Type.getInternalName(ByteBuffer.class);

            boolean constructorOfNew = false;
            if (opcode == Opcodes.INVOKESPECIAL && name.equals("<init>") && !pendingNew.isEmpty()) {
                // otherwise, this is a this() or super() call
                String newType = pendingNew.pop();
                if (newType.equals(owner)) {
                    constructorOfNew = true;
                } else if (!newType.equals(NEW_WITHOUT_DUP)) {
                    // unexpected nesting, stop tracking
                    pendingNew.clear();
                }
            }

            if (owner.equals(arraysOwner) && name.equals("copyOf")
                && descriptor.equals(Type.getMethodDescriptor(Type.getType(byte[].class), Type.getType(byte[].class), Type.INT_TYPE))) {
                invokeStatic(ARRAYS_COPY_OF);
                return;
            } else if (owner.equals(arraysOwner) && name.equals("copyOfRange")
                && descriptor.equals(Type.getMethodDescriptor(Type.getType(byte[].class), Type.getType(byte[].class), Type.INT_TYPE, Type.INT_TYPE))) {
                invokeStatic(ARRAYS_COPY_OF_RANGE);
                return;
            } else if (owner.equals(systemOwner) && name.equals("arraycopy")) {
                invokeStatic(SYSTEM_ARRAYCOPY);
                return;
            } else if (name.equals("array") && owner.equals(Type.getInternalName(ByteBuf.class))) {
                invokeStatic(BYTE_BUF_ARRAY);
                return;
            } else if (owner.equals(byteBufferOwner) && opcode == Opcodes.INVOKESTATIC && name.equals("wrap")
                && descriptor.equals(Type.getMethodDescriptor(BYTE_BUFFER_WRAP))) {
                invokeStatic(BYTE_BUFFER_WRAP);
                return;
            } else if (owner.equals(byteBufferOwner) && opcode == Opcodes.INVOKESTATIC && name.equals("wrap")
                && descriptor.equals(Type.getMethodDescriptor(BYTE_BUFFER_WRAP_RANGE))) {
                invokeStatic(BYTE_BUFFER_WRAP_RANGE);
                return;
            } else if (owner.equals(byteBufferOwner) && opcode == Opcodes.INVOKEVIRTUAL && name.equals("array") && descriptor.equals("()[B")) {
                invokeStatic(BYTE_BUFFER_ARRAY);
                return;
            } else if (typePool != null && (opcode != Opcodes.INVOKESPECIAL || !name.equals("<init>") || constructorOfNew)
                && passesByteArrayToUninstrumented(typePool, owner, name, descriptor)) {
                invokeUnwrapping(opcode, owner, name, descriptor);
                return;
            }
            super.visitMethodInsn(opcode, owner, name, descriptor, isInterface);
        }

        /**
         * Replace a call with an invokedynamic that passes the backing array instead of a guard array.
         */
        private void invokeUnwrapping(int opcode, String owner, String name, String descriptor) {
            Type ownerType = Type.getObjectType(owner);
            Type[] arguments = Type.getArgumentTypes(descriptor);
            String indyName = name;
            String indyDescriptor;
            int kind = opcode;
            if (opcode == Opcodes.INVOKESTATIC) {
                indyDescriptor = descriptor;
            } else if (name.equals("<init>")) {
                indyName = "init";
                indyDescriptor = Type.getMethodDescriptor(ownerType, arguments);
                kind = Opcodes.NEW;
            } else {
                Type[] withReceiver = new Type[arguments.length + 1];
                withReceiver[0] = ownerType;
                System.arraycopy(arguments, 0, withReceiver, 1, arguments.length);
                indyDescriptor = Type.getMethodDescriptor(Type.getReturnType(descriptor), withReceiver);
            }
            super.visitInvokeDynamicInsn(indyName, indyDescriptor, BOOTSTRAP_CALL, kind, ownerType);
            if (kind == Opcodes.NEW) {
                // the stack is now: uninitialized, uninitialized (from NEW and DUP), constructed object.
                // Drop the uninitialized references, without exceeding the original stack size.
                super.visitInsn(Opcodes.SWAP);
                super.visitInsn(Opcodes.POP);
                super.visitInsn(Opcodes.SWAP);
                super.visitInsn(Opcodes.POP);
            }
        }

        private void invokeStatic(Method method) {
            super.visitMethodInsn(
                Opcodes.INVOKESTATIC,
                Type.getInternalName(method.getDeclaringClass()),
                method.getName(),
                Type.getMethodDescriptor(method),
                false
            );
        }
    }
}
