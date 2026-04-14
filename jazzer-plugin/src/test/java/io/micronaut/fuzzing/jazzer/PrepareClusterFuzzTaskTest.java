package io.micronaut.fuzzing.jazzer;

import org.junit.jupiter.api.Test;

import java.util.List;
import java.util.Map;
import java.util.Set;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

class PrepareClusterFuzzTaskTest {
    @Test
    void uniqueSimpleNames() {
        Map<String, String> names = PrepareClusterFuzzTask.assignTargetNames(
            List.of("com.foo.A", "com.foo.B", "com.foo.C")
        );
        assertEquals("A", names.get("com.foo.A"), "com.foo.A must map to A");
        assertEquals("B", names.get("com.foo.B"), "com.foo.B must map to B");
        assertEquals("C", names.get("com.foo.C"), "com.foo.C must map to C");

        assertEquals(Set.of("A", "B", "C"), Set.copyOf(names.values()));
    }

    @Test
    void partialPackagePrefixStripped() {
        Map<String, String> names = PrepareClusterFuzzTask.assignTargetNames(
            List.of("com.foo.A", "com.bar.A", "com.baz.A", "com.foo.B", "com.foo.C")
        );
        assertEquals("foo_A", names.get("com.foo.A"), "com.foo.A must map to foo_A");
        assertEquals("bar_A", names.get("com.bar.A"), "com.bar.A must map to bar_A");
        assertEquals("baz_A", names.get("com.baz.A"), "com.baz.A must map to baz_A");

        assertEquals("B", names.get("com.foo.B"), "com.foo.B must map to B");
        assertEquals("C", names.get("com.foo.C"), "com.foo.C must map to C");

        assertEquals(Set.of("foo_A", "bar_A", "baz_A", "B", "C"), Set.copyOf(names.values()));
    }
    @Test
    void fullPrefixWhenNoCommonPackage() {
        Map<String, String> names = PrepareClusterFuzzTask.assignTargetNames(
            List.of("com.foo.A", "com.bar.A", "org.baz.A", "com.foo.B", "com.foo.C")
        );

        assertEquals("com_foo_A", names.get("com.foo.A"), "com.foo.A must map to com_foo_A");
        assertEquals("com_bar_A", names.get("com.bar.A"), "com.bar.A must map to com_bar_A");
        assertEquals("org_baz_A", names.get("org.baz.A"), "org.baz.A must map to org_baz_A");

        assertEquals("B", names.get("com.foo.B"), "com.foo.B must map to B");
        assertEquals("C", names.get("com.foo.C"), "com.foo.C must map to C");

        assertEquals(Set.of("com_foo_A", "com_bar_A", "org_baz_A", "B", "C"), Set.copyOf(names.values()));
    }

    @Test
    void singleTargetGetsSimpleName() {
        Map<String, String> names = PrepareClusterFuzzTask.assignTargetNames(
            List.of("com.example.MyFuzzer")
        );

        assertEquals(1, names.size());
        assertEquals("MyFuzzer", names.get("com.example.MyFuzzer"));
    }

    @Test
    void emptyInputReturnsEmptyMap() {
        Map<String, String> names = PrepareClusterFuzzTask.assignTargetNames(List.of());
        assertTrue(names.isEmpty());
    }
    @Test
    void assignedNamesAreAlwaysUnique() {
        List<String> inputs = List.of(
            "a.b.c.Target", "a.b.d.Target", "a.e.Target",
            "x.y.Other", "x.z.Other"
        );
        Map<String, String> names = PrepareClusterFuzzTask.assignTargetNames(inputs);

        assertEquals(names.size(), Set.copyOf(names.values()).size(),
            "all assigned names must be unique");
    }
}
