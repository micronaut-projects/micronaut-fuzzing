package io.micronaut.fuzzing.jazzer;

import org.junit.jupiter.api.Test;

import java.util.List;
import java.util.Map;
import java.util.Set;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertSame;
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

    @Test
    void capsCoverageClassFileMajorVersion() {
        byte[] classFile = minimalClassFile(69);

        byte[] compatible = PrepareClusterFuzzTask.limitClassFileMajorVersion(classFile, 68);

        assertEquals(68, classFileMajorVersion(compatible));
        assertEquals(69, classFileMajorVersion(classFile));
    }

    @Test
    void leavesEqualClassFileVersionUnchanged() {
        byte[] classFile = minimalClassFile(68);

        byte[] compatible = PrepareClusterFuzzTask.limitClassFileMajorVersion(classFile, 68);

        assertArrayEquals(classFile, compatible);
        assertSame(classFile, compatible);
    }

    @Test
    void leavesOlderClassFileVersionUnchanged() {
        byte[] classFile = minimalClassFile(61);

        byte[] compatible = PrepareClusterFuzzTask.limitClassFileMajorVersion(classFile, 68);

        assertArrayEquals(classFile, compatible);
        assertSame(classFile, compatible);
    }

    @Test
    void leavesNonClassFileBytesUnchanged() {
        byte[] bytes = new byte[] {1, 2, 3, 4};

        byte[] compatible = PrepareClusterFuzzTask.limitClassFileMajorVersion(bytes, 68);

        assertArrayEquals(bytes, compatible);
        assertSame(bytes, compatible);
    }

    @Test
    void coverageClassFileMajorVersionScriptHandlesJazzerDumpClassesDir() {
        String script = PrepareClusterFuzzTask.coverageClassFileMajorVersionScript(68);

        assertTrue(script.contains("jazzer_status=$?"));
        assertTrue(script.contains("--dump_classes_dir=*|-dump_classes_dir=*"));
        assertTrue(script.contains("--dump_classes_dir|-dump_classes_dir"));
        assertTrue(script.contains("python3 - \"68\""));
        assertTrue(script.contains("exit \"$jazzer_status\""));
    }

    private static byte[] minimalClassFile(int majorVersion) {
        byte[] classFile = new byte[] {(byte) 0xca, (byte) 0xfe, (byte) 0xba, (byte) 0xbe, 0, 0, 0, 0};
        classFile[6] = (byte) (majorVersion >>> 8);
        classFile[7] = (byte) majorVersion;
        return classFile;
    }

    private static int classFileMajorVersion(byte[] classFile) {
        return ((classFile[6] & 0xff) << 8) | (classFile[7] & 0xff);
    }

}
