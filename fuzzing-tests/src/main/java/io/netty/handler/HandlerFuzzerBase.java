// Copyright 2024 Google LLC
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//
////////////////////////////////////////////////////////////////////////////////

package io.netty.handler;

import com.code_intelligence.jazzer.api.FuzzedDataProvider;
import io.micronaut.fuzzing.Dict;
import io.micronaut.fuzzing.FlagAppender;
import io.micronaut.fuzzing.http.CustomResourceLeakDetector;
import io.micronaut.fuzzing.util.ByteSplitter;
import io.netty.buffer.ByteBuf;
import io.netty.channel.embedded.EmbeddedChannel;
import io.netty.util.internal.PlatformDependent;

/**
 * Base class for fuzzing the input of an inbound handler. Will report exceptions thrown by the handler.
 */
@Dict(HandlerFuzzerBase.SEPARATOR)
public abstract class HandlerFuzzerBase {
    static final String SEPARATOR = "SEP";
    static final ByteSplitter SPLITTER = ByteSplitter.create(SEPARATOR);

    static {
        CustomResourceLeakDetector.register();
    }

    protected final EmbeddedChannel channel = new EmbeddedChannel();

    public void test(FuzzedDataProvider provider) {
        byte[] allBytes = provider.consumeRemainingAsBytes();
        ByteSplitter.ChunkIterator itr = SPLITTER.splitIterator(allBytes);
        while (itr.hasNext() && channel.isOpen()) {
            itr.proceed();
            ByteBuf buffer = channel.alloc().buffer(itr.length());
            buffer.writeBytes(allBytes, itr.start(), itr.length());
            try {
                channel.writeInbound(buffer);
            } catch (Exception e) {
                onException(e);
                break; // cancel further input, but still release
            }
        }
        try {
            channel.finishAndReleaseAll();
        } catch (Exception e) {
            onException(e);
        }
        CustomResourceLeakDetector.reportLeaks();
        CustomResourceLeakDetector.reportStillOpen();
        FlagAppender.checkTriggered();
    }

    protected void onException(Exception e) {
        PlatformDependent.throwException(e);
    }
}
