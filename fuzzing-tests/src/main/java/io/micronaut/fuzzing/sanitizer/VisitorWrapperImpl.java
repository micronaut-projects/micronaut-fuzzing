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
        return new ClassVisitorImpl(Opcodes.ASM9, classVisitor);
    }

    private static final class ClassVisitorImpl extends ClassVisitor {
        private boolean hasBooleanArrayField;

        ClassVisitorImpl(int api, ClassVisitor classVisitor) {
            super(api, classVisitor);
        }

        @Override
        public FieldVisitor visitField(int access, String name, String descriptor, String signature, Object value) {
            if (BOOLEAN_ARRAY.equals(descriptor)) {
                hasBooleanArrayField = true;
            }
            return super.visitField(access, name, descriptor, signature, value);
        }

        @Override
        public MethodVisitor visitMethod(int access, String name, String descriptor, String signature, String[] exceptions) {
            MethodVisitorImpl methodVisitor = new MethodVisitorImpl(
                Opcodes.ASM9,
                super.visitMethod(access, name, descriptor, signature, exceptions)
            );
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
        private boolean ohNoBooleanArray;

        MethodVisitorImpl(int api, MethodVisitor methodVisitor) {
            super(api, methodVisitor);
        }

        @Override
        public void visitFieldInsn(int opcode, String owner, String name, String descriptor) {
            if (!ohNoBooleanArray && BOOLEAN_ARRAY.equals(descriptor)) {
                ohNoBooleanArray = true;
            }
            super.visitFieldInsn(opcode, owner, name, descriptor);
        }

        @Override
        public void visitIntInsn(int opcode, int operand) {
            if (!ohNoBooleanArray && opcode == Opcodes.NEWARRAY && operand == Opcodes.T_BOOLEAN) {
                ohNoBooleanArray = true;
            }
            super.visitIntInsn(opcode, operand);
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
            // Also treat any method that mentions boolean[] in its signature (parameters or return)
            // as an escape hatch source. This covers synthetic accessors returning [Z from outer classes.
            if (!ohNoBooleanArray && descriptor.contains(BOOLEAN_ARRAY)) {
                ohNoBooleanArray = true;
            }
            String arraysOwner = Type.getInternalName(Arrays.class);
            String systemOwner = Type.getInternalName(System.class);

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
}
