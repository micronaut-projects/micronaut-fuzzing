package io.micronaut.fuzzing.sanitizer;

import net.bytebuddy.agent.builder.AgentBuilder;
import net.bytebuddy.asm.TypeConstantAdjustment;
import net.bytebuddy.description.NamedElement;
import net.bytebuddy.description.type.TypeDescription;
import net.bytebuddy.dynamic.DynamicType;
import net.bytebuddy.matcher.ElementMatcher;
import net.bytebuddy.matcher.ElementMatchers;
import net.bytebuddy.utility.JavaModule;

import java.lang.instrument.Instrumentation;
import java.lang.reflect.Method;
import java.security.ProtectionDomain;
import java.util.List;

public class SanitizerTransformer implements AgentBuilder.Transformer {
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

        return builder
            .visit(TypeConstantAdjustment.INSTANCE)
            .visit(new VisitorWrapperImpl());
    }

    public static void installLocally() {
        String externalJazzerArgs = System.getenv("EXTERNAL_JAZZER_ARGS");
        if (externalJazzerArgs != null && externalJazzerArgs.contains("--nohooks")) {
            System.err.println("Refusing to install custom sanitizer because of `--nohooks` jazzer argument. This prevents interference with jacoco in coverage checking.");
            return;
        }

        try {
            Method m = Class.forName("com.code_intelligence.jazzer.third_party.net.bytebuddy.agent.ByteBuddyAgent").getMethod("install");
            install((Instrumentation) m.invoke(null));
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
            "sun",
            "java",
            "jdk",
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
}
