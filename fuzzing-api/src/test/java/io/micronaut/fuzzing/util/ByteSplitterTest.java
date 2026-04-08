package io.micronaut.fuzzing.util;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;

import java.nio.charset.StandardCharsets;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;


class ByteSplitterTest {
    @ParameterizedTest
    @ValueSource(strings = {
        "",            // single empty chunk (split("SEP",-1) on "" → [""])
        "foo",         // no separator → one chunk
        "fooSEPbar",   // one separator → two chunks
        "fooSEPbarSEP", // trailing separator → three chunks, last is empty
        "fooSEPSEPbarSEP",// consecutive separators → four chunks, one is empty
        "SEPfoo",
        "SEPSEPSEP"
    })
    void splitsMatchJavaStringSplit(String input) {
        String[] expected = input.split("SEP", -1);
        ByteSplitter splitter = ByteSplitter.create("SEP");
        ByteSplitter.ChunkIterator iterator = splitter.splitIterator(input.getBytes(StandardCharsets.UTF_8));

        int i = 0;
        while (iterator.hasNext()) {
            iterator.proceed();
            String expectedPiece = expected[i++];
            assertEquals(expectedPiece, iterator.asString(),
                "chunk " + i + " asString() mismatch");
            assertArrayEquals(expectedPiece.getBytes(StandardCharsets.UTF_8), iterator.asByteArray(),
                "chunk " + i + " asByteArray() mismatch");
            assertEquals(expectedPiece, input.substring(iterator.start(), iterator.start() + iterator.length()),
                "chunk " + i + " start/length window mismatch");
        }


        assertEquals(expected.length, i,
            "iterator produced " + i + " chunks but expected " + expected.length);
    }

    // -------------------------------------------------------------------------
    // Error-path contract: calling accessors before proceed()
    // -------------------------------------------------------------------------

    @Test
    void accessorsBeforeProceedThrow() {
        ByteSplitter.ChunkIterator iterator =
            ByteSplitter.create("SEP").splitIterator("fooSEPbar".getBytes(StandardCharsets.UTF_8));

        assertThrows(IllegalStateException.class, iterator::asString,
            "asString() before proceed() must throw");
        assertThrows(IllegalStateException.class, iterator::asByteArray,
            "asByteArray() before proceed() must throw");
        assertThrows(IllegalStateException.class, iterator::start,
            "start() before proceed() must throw");
        assertThrows(IllegalStateException.class, iterator::length,
            "length() before proceed() must throw");
    }




    // -------------------------------------------------------------------------
    // Binary (non-UTF-8) input
    // -------------------------------------------------------------------------

    @Test
    void binaryInputSplitsCorrectly() {
        byte[] sep = "SEP".getBytes(StandardCharsets.UTF_8);
        byte[] chunk0 = {0x01, 0x02};
        byte[] chunk1 = {(byte) 0xFF, (byte) 0xFE};
        byte[] input = new byte[chunk0.length + sep.length + chunk1.length];
        System.arraycopy(chunk0, 0, input, 0, chunk0.length);
        System.arraycopy(sep,    0, input, chunk0.length, sep.length);
        System.arraycopy(chunk1, 0, input, chunk0.length + sep.length, chunk1.length);

        ByteSplitter.ChunkIterator iter = ByteSplitter.create("SEP").splitIterator(input);

        iter.proceed();
        assertArrayEquals(chunk0, iter.asByteArray(), "first binary chunk");

        iter.proceed();
        assertArrayEquals(chunk1, iter.asByteArray(), "second binary chunk");

        assertEquals(false, iter.hasNext(), "no more chunks expected");
    }
}
