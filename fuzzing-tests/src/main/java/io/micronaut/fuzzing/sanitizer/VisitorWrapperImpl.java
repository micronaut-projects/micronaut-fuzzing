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
import net.bytebuddy.description.method.MethodList;
import net.bytebuddy.description.type.TypeDescription;
import net.bytebuddy.implementation.Implementation;
import net.bytebuddy.jar.asm.ClassVisitor;
import net.bytebuddy.jar.asm.FieldVisitor;
import net.bytebuddy.jar.asm.MethodVisitor;
import net.bytebuddy.jar.asm.Opcodes;
import net.bytebuddy.jar.asm.Type;
import net.bytebuddy.pool.TypePool;

import java.lang.reflect.Method;
import java.util.Arrays;

/**
 * ASM visitor wrapper that redirects selected byte-array operations to sanitizer helpers.
 */
final class VisitorWrapperImpl extends AsmVisitorWrapper.AbstractBase {
    private static final String BOOLEAN_ARRAY = "[Z";
    private static final boolean DEBUG = Boolean.parseBoolean(System.getenv("FUZZING_SANITIZER_DEBUG"));
    private static final String DEBUG_CLASS = System.getenv().getOrDefault("FUZZING_SANITIZER_DEBUG_CLASS", "io/netty/util/ByteProcessor");

    private static final Method BALOAD;
    private static final Method BASTORE;
    private static final Method BYTE_BUF_ARRAY;
    private static final Method ARRAYS_COPY_OF;
    private static final Method ARRAYS_COPY_OF_RANGE;
    private static final Method SYSTEM_ARRAYCOPY;

    static {
        try {
            BALOAD = ByteBufArraySanitizer.class.getMethod("baload", byte[].class, int.class);
            BASTORE = ByteBufArraySanitizer.class.getMethod("bastore", byte[].class, int.class, byte.class);
            BYTE_BUF_ARRAY = ByteBufArraySanitizer.class.getMethod("byteBufArray", ByteBuf.class);
            ARRAYS_COPY_OF = ByteBufArraySanitizer.class.getMethod("arraysCopyOf", byte[].class, int.class);
            ARRAYS_COPY_OF_RANGE = ByteBufArraySanitizer.class.getMethod("arraysCopyOfRange", byte[].class, int.class, int.class);
            SYSTEM_ARRAYCOPY = ByteBufArraySanitizer.class.getMethod("systemArraycopy", Object.class, int.class, Object.class, int.class, int.class);
        } catch (NoSuchMethodException e) {
            throw new RuntimeException(e);
        }
    }

    @Override
    public ClassVisitor wrap(TypeDescription typeDescription, ClassVisitor classVisitor, Implementation.Context context, TypePool typePool, FieldList<FieldDescription.InDefinedShape> fieldList, MethodList<?> methodList, int i, int i1) {
        return new ClassVisitorImpl(Opcodes.ASM9, classVisitor, typeDescription.getInternalName());
    }

    private static final class ClassVisitorImpl extends ClassVisitor {
        private final String owner;
        private boolean hasBooleanArrayField;

        ClassVisitorImpl(int api, ClassVisitor classVisitor, String owner) {
            super(api, classVisitor);
            this.owner = owner;
        }

        @Override
        public FieldVisitor visitField(int access, String name, String descriptor, String signature, Object value) {
            if (BOOLEAN_ARRAY.equals(descriptor)) {
                hasBooleanArrayField = true;
                debug(owner, "field boolean[] detected: " + name + ' ' + descriptor);
            }
            return super.visitField(access, name, descriptor, signature, value);
        }

        @Override
        public MethodVisitor visitMethod(int access, String name, String descriptor, String signature, String[] exceptions) {
            MethodVisitorImpl methodVisitor = new MethodVisitorImpl(
                Opcodes.ASM9,
                super.visitMethod(access, name, descriptor, signature, exceptions),
                owner,
                name
            );
            if (descriptor.contains(BOOLEAN_ARRAY)) {
                methodVisitor.ohNoBooleanArray = true;
                debug(owner, name + " boolean[] from method descriptor: " + descriptor);
            }
            if ("<clinit>".equals(name) && hasBooleanArrayField) {
                methodVisitor.ohNoBooleanArray = true;
                debug(owner, name + " boolean[] from class field presence");
            }
            return methodVisitor;
        }
    }

    private static final class MethodVisitorImpl extends MethodVisitor {
        private final String owner;
        private final String methodName;
        private boolean ohNoBooleanArray;

        MethodVisitorImpl(int api, MethodVisitor methodVisitor, String owner, String methodName) {
            super(api, methodVisitor);
            this.owner = owner;
            this.methodName = methodName;
        }

        @Override
        public void visitFieldInsn(int opcode, String owner, String name, String descriptor) {
            if (!ohNoBooleanArray && BOOLEAN_ARRAY.equals(descriptor)) {
                ohNoBooleanArray = true;
                debug(this.owner, methodName + " boolean[] from field access: " + owner + '.' + name + ' ' + descriptor);
            }
            super.visitFieldInsn(opcode, owner, name, descriptor);
        }

        @Override
        public void visitIntInsn(int opcode, int operand) {
            if (!ohNoBooleanArray && opcode == Opcodes.NEWARRAY && operand == Opcodes.T_BOOLEAN) {
                ohNoBooleanArray = true;
                debug(owner, methodName + " boolean[] from NEWARRAY T_BOOLEAN");
            }
            super.visitIntInsn(opcode, operand);
        }

        @Override
        public void visitFrame(int type, int numLocal, Object[] local, int numStack, Object[] stack) {
            for (Object o : local) {
                if (BOOLEAN_ARRAY.equals(o)) {
                    ohNoBooleanArray = true;
                    debug(owner, methodName + " boolean[] from frame local: " + Arrays.toString(local) + " stack=" + Arrays.toString(stack));
                    break;
                }
            }
            for (Object o : stack) {
                if (BOOLEAN_ARRAY.equals(o)) {
                    ohNoBooleanArray = true;
                    debug(owner, methodName + " boolean[] from frame stack: locals=" + Arrays.toString(local) + " stack=" + Arrays.toString(stack));
                    break;
                }
            }

            super.visitFrame(type, numLocal, local, numStack, stack);
        }

        @Override
        public void visitInsn(int opcode) {
            if (ohNoBooleanArray) {
                super.visitInsn(opcode);
                return;
            }

            if (opcode == Opcodes.BALOAD) {
                debug(owner, methodName + " rewriting BALOAD");
                invokeStatic(BALOAD);
            } else if (opcode == Opcodes.BASTORE) {
                debug(owner, methodName + " rewriting BASTORE");
                invokeStatic(BASTORE);
            } else {
                super.visitInsn(opcode);
            }
        }

        @Override
        public void visitMethodInsn(int opcode, String owner, String name, String descriptor, boolean isInterface) {
            if (!ohNoBooleanArray && descriptor.contains(BOOLEAN_ARRAY)) {
                ohNoBooleanArray = true;
                debug(this.owner, methodName + " boolean[] from invoked method descriptor: " + owner + '.' + name + descriptor);
            }
            String arraysOwner = Type.getInternalName(Arrays.class);
            String systemOwner = Type.getInternalName(System.class);

            if (owner.equals(arraysOwner) && name.equals("copyOf")
                && descriptor.equals(Type.getMethodDescriptor(Type.getType(byte[].class), Type.getType(byte[].class), Type.INT_TYPE))) {
                debug(this.owner, methodName + " rewriting Arrays.copyOf(byte[]) ");
                invokeStatic(ARRAYS_COPY_OF);
                return;
            } else if (owner.equals(arraysOwner) && name.equals("copyOfRange")
                && descriptor.equals(Type.getMethodDescriptor(Type.getType(byte[].class), Type.getType(byte[].class), Type.INT_TYPE, Type.INT_TYPE))) {
                debug(this.owner, methodName + " rewriting Arrays.copyOfRange(byte[]) ");
                invokeStatic(ARRAYS_COPY_OF_RANGE);
                return;
            } else if (owner.equals(systemOwner) && name.equals("arraycopy")) {
                debug(this.owner, methodName + " rewriting System.arraycopy");
                invokeStatic(SYSTEM_ARRAYCOPY);
                return;
            } else if (name.equals("array") && owner.equals(Type.getInternalName(ByteBuf.class))) {
                debug(this.owner, methodName + " rewriting ByteBuf.array()");
                invokeStatic(BYTE_BUF_ARRAY);
                return;
            }
            super.visitMethodInsn(opcode, owner, name, descriptor, isInterface);
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

    private static void debug(String owner, String message) {
        if (DEBUG && DEBUG_CLASS.equals(owner)) {
            System.err.println("[sanitizer-debug] " + owner + " :: " + message);
        }
    }
}
