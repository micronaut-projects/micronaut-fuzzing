package io.micronaut.fuzzing.sanitizer;

import io.netty.buffer.ByteBuf;
import io.netty.buffer.ByteBufAllocator;
import io.netty.handler.codec.http.HttpRequestDecoder;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.util.Arrays;
import java.util.List;
import java.util.concurrent.atomic.AtomicReference;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

public class SanitizerTransformerTest {
    @BeforeAll
    static void init() {
        SanitizerTransformer.installLocally();
    }

    private static volatile int sink;

    @Test
    public void loadsAreAccurate() {
        ByteBuf buffer = ByteBufAllocator.DEFAULT.heapBuffer(16);
        try {
            buffer.writeByte(1);
            buffer.writeByte(2);
            buffer.writeByte(3);

            byte[] array = buffer.array();
            assertEquals(1, array[0]);
            assertEquals(2, array[1]);
            assertEquals(3, array[2]);
            array[0] = 4;
            assertEquals(4, array[0]);

            byte[] tmp = new byte[3];
            System.arraycopy(array, 0, tmp, 0, 3);
            assertEquals(4, tmp[0]);
            assertEquals(2, tmp[1]);
            assertEquals(3, tmp[2]);

            tmp = Arrays.copyOf(array, 3);
            assertEquals(4, tmp[0]);
            assertEquals(2, tmp[1]);
            assertEquals(3, tmp[2]);

            tmp = Arrays.copyOfRange(array, 1, 3);
            assertEquals(2, tmp[0]);
            assertEquals(3, tmp[1]);
        } finally {
            buffer.release();
        }
    }

    @Test
    public void aload() {
        ByteBuf buffer = ByteBufAllocator.DEFAULT.heapBuffer(16);
        try {
            assertScenarioReportsFinding(() -> {
                if (buffer.arrayOffset() == 0) {
                    sink = buffer.array()[16];
                } else {
                    sink = buffer.array()[0];
                }
            });
        } finally {
            buffer.release();
        }
    }

    @Test
    public void arraysCopyOf_oob() {
        ByteBuf parent = ByteBufAllocator.DEFAULT.heapBuffer(32);
        ByteBuf buffer = parent.retainedSlice(8, 16);
        try {
            assertScenarioReportsFinding(() -> Arrays.copyOf(buffer.array(), 1));
        } finally {
            buffer.release();
            parent.release();
        }
    }

    @Test
    public void arraysCopyOfRange_oob() {
        ByteBuf parent = ByteBufAllocator.DEFAULT.heapBuffer(32);
        ByteBuf buffer = parent.retainedSlice(8, 16);
        try {
            assertScenarioReportsFinding(() -> Arrays.copyOfRange(buffer.array(), 0, 1));
        } finally {
            buffer.release();
            parent.release();
        }
    }

    @Test
    public void systemArraycopy_oob_source() {
        ByteBuf parent = ByteBufAllocator.DEFAULT.heapBuffer(32);
        ByteBuf buffer = parent.retainedSlice(8, 16);
        byte[] dest = new byte[1];
        try {
            assertScenarioReportsFinding(() -> System.arraycopy(buffer.array(), 0, dest, 0, 1));
        } finally {
            buffer.release();
            parent.release();
        }
    }

    @Test
    public void systemArraycopy_oob_dest() {
        ByteBuf parent = ByteBufAllocator.DEFAULT.heapBuffer(32);
        ByteBuf buffer = parent.retainedSlice(8, 16);
        byte[] src = new byte[1];
        try {
            assertScenarioReportsFinding(() -> System.arraycopy(src, 0, buffer.array(), 0, 1));
        } finally {
            buffer.release();
            parent.release();
        }
    }

    @Test
    public void realJazzerHookStillReportsFinding() throws IOException, InterruptedException {
        String javaHome = System.getProperty("java.home");
        String javaBin = javaHome + "/bin/java";
        String classpath = System.getProperty("java.class.path");
        Process process = new ProcessBuilder(List.of(
            javaBin,
            "--enable-preview",
            "-cp",
            classpath,
            TestOutOfBoundsTarget.class.getName(),
            "aload"
        )).start();
        String output;
        try (InputStream stdout = process.getInputStream();
             InputStream stderr = process.getErrorStream()) {
            output = readAll(stdout) + readAll(stderr);
        }
        int exitCode = process.waitFor();
        assertTrue(exitCode != 0, () -> "Expected non-zero exit for Jazzer hook integration, output:\n" + output);
        assertTrue(output.contains("Out-of-bounds array access"), () -> "Expected sanitizer finding in output, output:\n" + output);
    }

    @Test
    public void httpObjectDecoderInitializes() {
        new HttpRequestDecoder();
    }

    private static void assertScenarioReportsFinding(ThrowingRunnable runnable) {
        AtomicReference<String> reported = new AtomicReference<>();
        FindingReporter.Reporter previous = FindingReporter.replaceForTesting(reported::set);
        try {
            runnable.run();
            assertEquals("Out-of-bounds array access", reported.get());
        } finally {
            FindingReporter.replaceForTesting(previous);
        }
    }

    private static String readAll(InputStream inputStream) throws IOException {
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        inputStream.transferTo(out);
        return out.toString(StandardCharsets.UTF_8);
    }

    @FunctionalInterface
    private interface ThrowingRunnable {
        void run();
    }
}
