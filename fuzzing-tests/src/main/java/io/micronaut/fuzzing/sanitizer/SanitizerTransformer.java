package io.micronaut.fuzzing.sanitizer;

import net.bytebuddy.ByteBuddy;
import net.bytebuddy.NamingStrategy;
import net.bytebuddy.agent.builder.AgentBuilder;
import net.bytebuddy.asm.TypeConstantAdjustment;
import net.bytebuddy.description.type.TypeDescription;
import net.bytebuddy.dynamic.DynamicType;
import net.bytebuddy.dynamic.scaffold.InstrumentedType;
import net.bytebuddy.dynamic.scaffold.TypeValidation;
import net.bytebuddy.matcher.ElementMatchers;
import net.bytebuddy.utility.JavaModule;

import java.lang.instrument.Instrumentation;
import java.lang.reflect.Method;
import java.security.ProtectionDomain;

public class SanitizerTransformer implements AgentBuilder.Transformer {
    @Override
    public DynamicType.Builder<?> transform(DynamicType.Builder<?> builder, TypeDescription typeDescription, ClassLoader classLoader, JavaModule javaModule, ProtectionDomain protectionDomain) {
        if (classLoader != null) {
            try {
                classLoader.loadClass(SanitizerBootstrap.class.getName());
            } catch (ClassNotFoundException e) {
                return builder;
            }
        }

        return builder
            .visit(TypeConstantAdjustment.INSTANCE)
            .visit(new VisitorWrapperImpl());
    }

    public static void installLocally() {
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
        new AgentBuilder.Default()
            .with(new ByteBuddy()
                .with(TypeValidation.DISABLED)
                .with(InstrumentedType.Factory.Default.FROZEN))
            .with(AgentBuilder.Listener.StreamWriting.toSystemError().withErrorsOnly())
            .with(AgentBuilder.RedefinitionStrategy.RETRANSFORMATION)
            .with(AgentBuilder.LambdaInstrumentationStrategy.DISABLED)
            .with(AgentBuilder.TypeStrategy.Default.REDEFINE)
            .with(AgentBuilder.InitializationStrategy.NoOp.INSTANCE)
            // this is the default ignore matcher except we don't ignore synthetic types
            .ignore(
                new AgentBuilder.RawMatcher.ForElementMatchers(ElementMatchers.any(), ElementMatchers.isBootstrapClassLoader().or(ElementMatchers.isExtensionClassLoader())))
            .or(new AgentBuilder.RawMatcher.ForElementMatchers(ElementMatchers.nameStartsWith("net.bytebuddy.")
                .and(ElementMatchers.not(ElementMatchers.nameStartsWith(NamingStrategy.BYTE_BUDDY_RENAME_PACKAGE + ".")))
                .or(ElementMatchers.nameStartsWith("sun.reflect.").or(ElementMatchers.nameStartsWith("jdk.internal.reflect.")))))
            .type(ElementMatchers.any()
                .and(ElementMatchers.not(ElementMatchers.nameStartsWith("net.bytebuddy.")))
                .and(ElementMatchers.not(ElementMatchers.nameStartsWith("com.code_intelligence.")))
                .and(ElementMatchers.not(ElementMatchers.nameStartsWith("com.sun")))
                .and(ElementMatchers.not(ElementMatchers.nameStartsWith(SanitizerBootstrap.class.getPackageName()))
                    .or(ElementMatchers.nameStartsWith(TestOutOfBoundsTarget.class.getName())))
            )
            .transform(new SanitizerTransformer())
            .installOn(instrumentation);
    }
}
