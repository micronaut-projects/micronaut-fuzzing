package io.micronaut.fuzzing.http;

import io.netty.buffer.ByteBuf;
import io.netty.buffer.ByteBufAllocator;
import io.netty.buffer.ByteBufUtil;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;

import java.nio.CharBuffer;
import java.nio.charset.StandardCharsets;
import java.util.List;

class ByteSeparatorTest {
    private static List<String> split(String input) {
        ByteBuf in = ByteBufUtil.encodeString(ByteBufAllocator.DEFAULT, CharBuffer.wrap(input), StandardCharsets.UTF_8);
        List<ByteBuf> separated = ByteSeparator.separate(in);
        List<String> out = separated.stream()
            .map(bb -> {
                String part = bb.toString(StandardCharsets.UTF_8);
                bb.release();
                return part;
            })
            .toList();
        Assertions.assertEquals(0, in.refCnt());
        for (ByteBuf piece : separated) {
            Assertions.assertEquals(0, piece.refCnt());
        }
        return out;
    }

    @Test
    public void split() {
        Assertions.assertEquals(List.of("foo", "bar"), split("foo" + ByteSeparator.SEPARATOR + "bar"));
        Assertions.assertEquals(List.of("foo", "bar", ""), split("foo" + ByteSeparator.SEPARATOR + "bar" + ByteSeparator.SEPARATOR));
    }
}
