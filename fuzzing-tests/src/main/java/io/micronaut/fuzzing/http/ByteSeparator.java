package io.micronaut.fuzzing.http;

import io.netty.buffer.ByteBuf;
import io.netty.buffer.ByteBufUtil;
import io.netty.buffer.Unpooled;

import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.List;
import java.util.function.Consumer;

/**
 * This class splits a byte input into multiple chunks in a fuzzer-friendly way, using the
 * {@link ByteSeparator#SEPARATOR}. Take care to add the separator to the fuzzer dictionary!
 */
public class ByteSeparator {
    static final String SEPARATOR = "SEP";
    private static final ByteBuf SEPARATOR_BYTES = Unpooled.copiedBuffer(SEPARATOR, StandardCharsets.UTF_8);

    private ByteSeparator() {
    }

    public static List<ByteBuf> separate(ByteBuf joint) {
        List<ByteBuf> result = new ArrayList<>();
        forEachPiece(joint, result::add);
        return result;
    }

    public static void forEachPiece(ByteBuf joint, Consumer<ByteBuf> consumer) {
        try {
            while (true) {
                int i = ByteBufUtil.indexOf(SEPARATOR_BYTES, joint);
                if (i == -1) {
                    break;
                }
                consumer.accept(joint.readRetainedSlice(i - joint.readerIndex()));
                joint.skipBytes(SEPARATOR_BYTES.readableBytes());
            }
            consumer.accept(joint.retain());
        } finally {
            joint.release();
        }
    }
}
