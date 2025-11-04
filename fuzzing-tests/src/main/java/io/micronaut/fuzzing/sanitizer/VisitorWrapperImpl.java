package io.micronaut.fuzzing.sanitizer;

import io.netty.buffer.ByteBuf;
import net.bytebuddy.asm.AsmVisitorWrapper;
import net.bytebuddy.description.field.FieldDescription;
import net.bytebuddy.description.field.FieldList;
import net.bytebuddy.description.method.MethodList;
import net.bytebuddy.description.type.TypeDescription;
import net.bytebuddy.implementation.Implementation;
import net.bytebuddy.jar.asm.ClassVisitor;
import net.bytebuddy.jar.asm.Handle;
import net.bytebuddy.jar.asm.MethodVisitor;
import net.bytebuddy.jar.asm.Opcodes;
import net.bytebuddy.jar.asm.Type;
import net.bytebuddy.pool.TypePool;

import java.lang.reflect.Method;

final class VisitorWrapperImpl extends AsmVisitorWrapper.AbstractBase {
    private static final String BOOLEAN_ARRAY = "[Z";

    @Override
    public ClassVisitor wrap(TypeDescription typeDescription, ClassVisitor classVisitor, Implementation.Context context, TypePool typePool, FieldList<FieldDescription.InDefinedShape> fieldList, MethodList<?> methodList, int i, int i1) {
        return new ClassVisitorImpl(Opcodes.ASM9, classVisitor);
    }

    private static final class ClassVisitorImpl extends ClassVisitor {
        ClassVisitorImpl(int api, ClassVisitor classVisitor) {
            super(api, classVisitor);
        }

        @Override
        public void visit(int version, int access, String name, String signature, String superName, String[] interfaces) {
            super.visit(Math.max(version, Opcodes.V1_8), access, name, signature, superName, interfaces);
        }

        @Override
        public MethodVisitor visitMethod(int access, String name, String descriptor, String signature, String[] exceptions) {
            MethodVisitorImpl methodVisitor = new MethodVisitorImpl(Opcodes.ASM9, super.visitMethod(access, name, descriptor, signature, exceptions));
            if (descriptor.contains(BOOLEAN_ARRAY)) {
                methodVisitor.ohNoBooleanArray = true;
            }
            return methodVisitor;
        }
    }

    private static final class MethodVisitorImpl extends MethodVisitor {
        boolean ohNoBooleanArray;

        MethodVisitorImpl(int api, MethodVisitor methodVisitor) {
            super(api, methodVisitor);
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
                indy(
                    SanitizerBootstrap.METHOD_BALOAD_BOOTSTRAP,
                    Type.getMethodDescriptor(Type.BYTE_TYPE, Type.getType(byte[].class), Type.INT_TYPE)
                );
            } else if (opcode == Opcodes.BASTORE) {
                indy(
                    SanitizerBootstrap.METHOD_BASTORE_BOOTSTRAP,
                    Type.getMethodDescriptor(Type.VOID_TYPE, Type.getType(byte[].class), Type.INT_TYPE, Type.BYTE_TYPE)
                );
            } else {
                super.visitInsn(opcode);
            }
        }

        @Override
        public void visitMethodInsn(int opcode, String owner, String name, String descriptor, boolean isInterface) {
            if (name.equals("array") && owner.equals(Type.getInternalName(ByteBuf.class))) {
                indy(
                    SanitizerBootstrap.METHOD_BYTE_BUF_ARRAY_BOOTSTRAP,
                    Type.getMethodDescriptor(Type.getType(byte[].class), Type.getType(ByteBuf.class))
                );
                return;
            }
            super.visitMethodInsn(opcode, owner, name, descriptor, isInterface);
        }

        private void indy(Method bootstrapMethod, String callSiteDescriptor, Object... args) {
            super.visitInvokeDynamicInsn(
                "foo",
                callSiteDescriptor,
                new Handle(
                    Opcodes.H_INVOKESTATIC,
                    Type.getInternalName(bootstrapMethod.getDeclaringClass()),
                    bootstrapMethod.getName(),
                    Type.getMethodDescriptor(bootstrapMethod),
                    false
                ),
                args
            );
        }
    }
}
