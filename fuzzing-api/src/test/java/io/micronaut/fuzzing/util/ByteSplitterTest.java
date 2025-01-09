package io.micronaut.fuzzing.util;

import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;

import java.nio.charset.StandardCharsets;

class ByteSplitterTest {
    @ParameterizedTest
    @ValueSource(strings = {
        "",
        "foo",
        "fooSEPbar",
        "fooSEPbarSEP",
        "fooSEPSEPbarSEP",
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
    }
}
