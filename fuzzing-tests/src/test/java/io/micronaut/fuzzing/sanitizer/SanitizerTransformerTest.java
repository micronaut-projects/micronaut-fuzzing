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

import static org.junit.jupiter.api.Assertions.assertEquals;
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
    public void aload() throws IOException, InterruptedException {
        assertScenarioReportsFinding("aload");
    }

    @Test
    public void arraysCopyOf_oob() throws IOException, InterruptedException {
        assertScenarioReportsFinding("copyOf");
    }

    @Test
    public void arraysCopyOfRange_oob() throws IOException, InterruptedException {
        assertScenarioReportsFinding("copyOfRange");
    }

    @Test
    public void systemArraycopy_oob_source() throws IOException, InterruptedException {
        assertScenarioReportsFinding("arraycopySource");
    }

    @Test
    public void systemArraycopy_oob_dest() throws IOException, InterruptedException {
        assertScenarioReportsFinding("arraycopyDest");
    }

    @Test
    public void httpObjectDecoderInitializes() {
        new HttpRequestDecoder();
    }

    private static void assertScenarioReportsFinding(String scenario) throws IOException, InterruptedException {
        String javaHome = System.getProperty("java.home");
        String javaBin = javaHome + "/bin/java";
        String classpath = System.getProperty("java.class.path");
        Process process = new ProcessBuilder(List.of(
            javaBin,
            "--enable-preview",
            "-cp",
            classpath,
            TestOutOfBoundsTarget.class.getName(),
            scenario
        )).start();
        String output;
        try (InputStream stdout = process.getInputStream();
             InputStream stderr = process.getErrorStream()) {
            output = readAll(stdout) + readAll(stderr);
        }
        int exitCode = process.waitFor();
        assertTrue(exitCode != 0, () -> "Expected non-zero exit for scenario " + scenario + ", output:\n" + output);
        assertTrue(output.contains("Out-of-bounds array access"), () -> "Expected sanitizer finding in output for scenario " + scenario + ", output:\n" + output);
    }

    private static String readAll(InputStream inputStream) throws IOException {
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        inputStream.transferTo(out);
        return out.toString(StandardCharsets.UTF_8);
    }
}
