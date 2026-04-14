package io.micronaut.fuzzing.util;

import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;

import java.nio.charset.StandardCharsets;

import static org.junit.jupiter.api.Assertions.*;
import static org.junit.jupiter.api.Assertions.assertArrayEquals;

class ByteSplitterTest {
    @ParameterizedTest
    @ValueSource(strings = {
        "",
        "foo",
        "fooSEPbar",
        "fooSEPbarSEP",
        "fooSEPSEPbarSEP",
        "SEPfoo",
        "SEPSEPSEP",
    })
    public void test(String input) {
        String[] expected = input.split("SEP", -1);
        ByteSplitter splitter = ByteSplitter.create("SEP");
        ByteSplitter.ChunkIterator iterator = splitter.splitIterator(input.getBytes(StandardCharsets.UTF_8));
        int i = 0;
        while (iterator.hasNext()) {
            iterator.proceed();
            String expectedPiece = expected[i++];
            Assertions.assertEquals(expectedPiece, iterator.asString());
            Assertions.assertArrayEquals(expectedPiece.getBytes(StandardCharsets.UTF_8), iterator.asByteArray());
            Assertions.assertEquals(expectedPiece, input.substring(iterator.start(), iterator.start() + iterator.length()));
        }
        assertEquals(expected.length, i,
            "iterator produced " + i + " chunks but expected " + expected.length);
    }
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
