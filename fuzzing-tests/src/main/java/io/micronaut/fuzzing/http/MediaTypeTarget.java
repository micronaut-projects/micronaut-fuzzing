package io.micronaut.fuzzing.http;

import com.code_intelligence.jazzer.api.FuzzedDataProvider;
import io.micronaut.http.MediaType;
import io.netty.buffer.Unpooled;
import io.netty.channel.Channel;

import java.util.ArrayList;
import java.util.List;

public class MediaTypeTarget {
    public static void fuzzerTestOneInput(FuzzedDataProvider input) throws Exception {
        List<String> strings = new ArrayList<>();
        while (input.remainingBytes() > 0 && strings.size() < 128) {
            strings.add(input.consumeString(32));
        }
        MediaType.orderedOf(strings);
    }
}
