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

import net.bytebuddy.agent.builder.AgentBuilder;
import net.bytebuddy.asm.TypeConstantAdjustment;
import net.bytebuddy.description.NamedElement;
import net.bytebuddy.description.type.TypeDescription;
import net.bytebuddy.dynamic.DynamicType;
import net.bytebuddy.dynamic.scaffold.TypeValidation;
import net.bytebuddy.matcher.ElementMatcher;
import net.bytebuddy.matcher.ElementMatchers;
import net.bytebuddy.utility.JavaModule;

import net.bytebuddy.jar.asm.ClassVisitor;
import net.bytebuddy.jar.asm.ClassWriter;
import net.bytebuddy.jar.asm.Opcodes;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardOpenOption;
import java.lang.instrument.Instrumentation;
import java.lang.reflect.Method;
import java.security.ProtectionDomain;
import java.util.List;

/**
 * Byte Buddy transformer that rewrites byte-array access patterns for sanitizer checks.
 */
public final class SanitizerTransformer implements AgentBuilder.Transformer {
    private static final boolean DEBUG_DUMP = Boolean.parseBoolean(System.getenv().getOrDefault("FUZZING_SANITIZER_DUMP", "false"));
    private static final String DEBUG_DUMP_CLASS = System.getenv().getOrDefault("FUZZING_SANITIZER_DUMP_CLASS", "io.netty.util.ByteProcessor");
    private static final Path DEBUG_DUMP_FILE = Path.of(System.getenv().getOrDefault("FUZZING_SANITIZER_DUMP_FILE", "build/byteprocessor-transformed.class"));
    private static volatile boolean installed;

    @Override
    public DynamicType.Builder<?> transform(DynamicType.Builder<?> builder, TypeDescription typeDescription, ClassLoader classLoader, JavaModule javaModule, ProtectionDomain protectionDomain) {
        if (classLoader == null) {
            return builder;
        }
        try {
            Class.forName("io.micronaut.fuzzing.sanitizer.ByteBufArraySanitizer", false, classLoader);
        } catch (ClassNotFoundException e) {
            return builder;
        }

        DynamicType.Builder<?> transformed = builder
            .visit(TypeConstantAdjustment.INSTANCE)
            .visit(new VisitorWrapperImpl());
        if (DEBUG_DUMP && DEBUG_DUMP_CLASS.equals(typeDescription.getName())) {
            transformed = transformed.visit(new BytecodeDumpWrapper(typeDescription.getName()));
        }
        return transformed;
    }

    public static void installLocally() {
        if (installed) {
            return;
        }
        String externalJazzerArgs = System.getenv("EXTERNAL_JAZZER_ARGS");
        if (externalJazzerArgs != null && externalJazzerArgs.contains("--nohooks")) {
            System.err.println("Refusing to install custom sanitizer because of `--nohooks` jazzer argument. This prevents interference with jacoco in coverage checking.");
            return;
        }

        try {
            Method m = Class.forName("com.code_intelligence.jazzer.third_party.net.bytebuddy.agent.ByteBuddyAgent").getMethod("install");
            Instrumentation instrumentation = (Instrumentation) m.invoke(null);
            install(instrumentation);
            installed = true;
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }

    /**
     * Install this transformer into the given {@link Instrumentation}.
     *
     * @param instrumentation The instrumentation used for modifying classes
     */
    public static void install(Instrumentation instrumentation) {
        List<String> excludedPackages = List.of(
            "com.code_intelligence",
            "com.sun",
            "net.bytebuddy",
            "org.gradle",
            "org.junit",
            "org.opentest4j",
            "sun",
            "java",
            "jdk",
            "worker.org.gradle",
            "io.netty.buffer" // need to ignore nested calls to .array
        );

        ElementMatcher.Junction<NamedElement> matcher = ElementMatchers.any()
            .and(ElementMatchers.not(ElementMatchers.named(ByteBufArraySanitizer.class.getName())));
        for (String excludedPackage : excludedPackages) {
            matcher = matcher.and(ElementMatchers.not(ElementMatchers.nameStartsWith(excludedPackage + '.')));
        }

        new AgentBuilder.Default()
            .disableClassFormatChanges()
            .with(AgentBuilder.Listener.StreamWriting.toSystemError().withErrorsOnly())
            .with(AgentBuilder.RedefinitionStrategy.RETRANSFORMATION)
            .with(AgentBuilder.RedefinitionStrategy.DiscoveryStrategy.Reiterating.INSTANCE)
            .type(matcher).transform(new SanitizerTransformer())
            .installOn(instrumentation);
    }
    private static final class BytecodeDumpWrapper extends net.bytebuddy.asm.AsmVisitorWrapper.AbstractBase {
        private final String className;

        private BytecodeDumpWrapper(String className) {
            this.className = className;
        }

        @Override
        public ClassVisitor wrap(TypeDescription instrumentedType, ClassVisitor classVisitor, net.bytebuddy.implementation.Implementation.Context implementationContext, net.bytebuddy.pool.TypePool typePool, net.bytebuddy.description.field.FieldList<net.bytebuddy.description.field.FieldDescription.InDefinedShape> fields, net.bytebuddy.description.method.MethodList<?> methods, int writerFlags, int readerFlags) {
            ClassWriter writer = new ClassWriter(0);
            return new ClassVisitor(Opcodes.ASM9, writer) {
                @Override
                public void visitEnd() {
                    super.visitEnd();
                    byte[] bytes = writer.toByteArray();
                    writeDump(className, bytes);
                    classVisitor.visitEnd();
                }

                @Override
                public void visit(int version, int access, String name, String signature, String superName, String[] interfaces) {
                    classVisitor.visit(version, access, name, signature, superName, interfaces);
                    super.visit(version, access, name, signature, superName, interfaces);
                }

                @Override
                public net.bytebuddy.jar.asm.FieldVisitor visitField(int access, String name, String descriptor, String signature, Object value) {
                    net.bytebuddy.jar.asm.FieldVisitor downstream = classVisitor.visitField(access, name, descriptor, signature, value);
                    net.bytebuddy.jar.asm.FieldVisitor upstream = super.visitField(access, name, descriptor, signature, value);
                    return new net.bytebuddy.jar.asm.FieldVisitor(Opcodes.ASM9, upstream) {
                        @Override
                        public void visitEnd() {
                            if (downstream != null) {
                                downstream.visitEnd();
                            }
                            super.visitEnd();
                        }
                    };
                }

                @Override
                public net.bytebuddy.jar.asm.MethodVisitor visitMethod(int access, String name, String descriptor, String signature, String[] exceptions) {
                    net.bytebuddy.jar.asm.MethodVisitor downstream = classVisitor.visitMethod(access, name, descriptor, signature, exceptions);
                    net.bytebuddy.jar.asm.MethodVisitor upstream = super.visitMethod(access, name, descriptor, signature, exceptions);
                    return new net.bytebuddy.jar.asm.MethodVisitor(Opcodes.ASM9, upstream) {
                        @Override
                        public void visitEnd() {
                            if (downstream != null) {
                                downstream.visitEnd();
                            }
                            super.visitEnd();
                        }
                    };
                }
            };
        }
    }

    private static void writeDump(String className, byte[] bytes) {
        try {
            Path parent = DEBUG_DUMP_FILE.getParent();
            if (parent != null) {
                Files.createDirectories(parent);
            }
            Files.write(DEBUG_DUMP_FILE, bytes);
            Path infoFile = DEBUG_DUMP_FILE.resolveSibling(DEBUG_DUMP_FILE.getFileName() + ".txt");
            Files.writeString(
                infoFile,
                className + System.lineSeparator() + bytes.length + System.lineSeparator(),
                StandardCharsets.UTF_8,
                StandardOpenOption.CREATE,
                StandardOpenOption.TRUNCATE_EXISTING
            );
            System.err.println("[sanitizer-dump] wrote transformed class " + className + " to " + DEBUG_DUMP_FILE.toAbsolutePath() + " bytes=" + bytes.length);
        } catch (IOException e) {
            System.err.println("[sanitizer-dump] failed to write dump for " + className + ": " + e.getMessage());
        }
    }

}
