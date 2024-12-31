package io.micronaut.fuzzing.jazzer;

import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;

import java.util.List;
import java.util.Set;

class PrepareClusterFuzzTaskTest {
    @Test
    void test() {
        testAssignTargetNames(
            List.of("com.foo.A", "com.foo.B", "com.foo.C"),
            Set.of("A", "B", "C")
        );
        testAssignTargetNames(
            List.of("com.foo.A", "com.bar.A", "com.baz.A", "com.foo.B", "com.foo.C"),
            Set.of("foo_A", "bar_A", "baz_A", "B", "C")
        );
        testAssignTargetNames(
            List.of("com.foo.A", "com.bar.A", "org.baz.A", "com.foo.B", "com.foo.C"),
            Set.of("com_foo_A", "com_bar_A", "org_baz_A", "B", "C")
        );
    }

    static void testAssignTargetNames(List<String> targetClasses, Set<String> targetNames) {
        Assertions.assertEquals(targetNames, Set.copyOf(PrepareClusterFuzzTask.assignTargetNames(targetClasses).values()));
    }
}
