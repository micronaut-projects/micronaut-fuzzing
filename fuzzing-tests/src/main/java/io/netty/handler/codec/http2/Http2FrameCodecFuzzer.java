/*
 * Copyright 2017-2026 original authors
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * https://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package io.netty.handler.codec.http2;

import io.netty.channel.embedded.EmbeddedChannel;
import com.code_intelligence.jazzer.api.FuzzedDataProvider;
import io.micronaut.fuzzing.FuzzTarget;
import io.micronaut.fuzzing.HttpDict;
import io.micronaut.fuzzing.runner.LocalJazzerRunner;
import io.netty.handler.HandlerFuzzerBase;


/**
 * Fuzzing support type.
 */
@FuzzTarget
@HttpDict
public class Http2FrameCodecFuzzer extends HandlerFuzzerBase {
    @Override
    protected EmbeddedChannel setUp() {
        EmbeddedChannel channel = new EmbeddedChannel();
        channel.pipeline()
            .addLast(Http2FrameCodecBuilder.forClient().build());
        return channel;
    }

    @Override
    protected void onException(Exception e) {
        if (e instanceof Http2Exception || e instanceof Http2FrameStreamException) {
            return;
        }
        if (isInvalidPushPromiseContentLength(e) || isDataOnReservedStream(e)) {
            return;
        }
        super.onException(e);
    }

    /**
     * A PUSH_PROMISE with an invalid content-length header (e.g. not a number) is not converted to a stream
     * error. Fixed by https://github.com/netty/netty/pull/17867.
     */
    private static boolean isInvalidPushPromiseContentLength(Exception e) {
        return e.getClass() == IllegalArgumentException.class
            && thrownBy(e, "io.netty.handler.codec.http.HttpUtil", "normalizeAndGetContentLength",
            "io.netty.handler.codec.http2.DefaultHttp2ConnectionDecoder$FrameReadListener", "onPushPromiseRead");
    }

    /**
     * A DATA frame on a stream in RESERVED_REMOTE state (promised by a PUSH_PROMISE, but no HEADERS yet) reaches
     * the reduced flow state of the stream, which throws. Fixed by https://github.com/netty/netty/pull/17868.
     */
    private static boolean isDataOnReservedStream(Exception e) {
        if (e.getClass() != UnsupportedOperationException.class) {
            return false;
        }
        String reducedFlowState = "io.netty.handler.codec.http2.DefaultHttp2LocalFlowController$2";
        String flowController = "io.netty.handler.codec.http2.DefaultHttp2LocalFlowController";
        return thrownBy(e, reducedFlowState, "endOfStream", flowController, "receiveFlowControlledFrame")
            || thrownBy(e, reducedFlowState, "receiveFlowControlledFrame", flowController, "receiveFlowControlledFrame");
    }

    private static boolean thrownBy(Exception e, String className, String methodName, String callerClassName, String callerMethodName) {
        StackTraceElement[] trace = e.getStackTrace();
        return trace.length >= 2
            && trace[0].getClassName().equals(className)
            && trace[0].getMethodName().equals(methodName)
            && trace[1].getClassName().equals(callerClassName)
            && trace[1].getMethodName().equals(callerMethodName);
    }

    public static void fuzzerTestOneInput(FuzzedDataProvider fuzzedDataProvider) {
        new Http2FrameCodecFuzzer().test(fuzzedDataProvider);
    }

    public static void main(String[] args) {
        LocalJazzerRunner.create(Http2FrameCodecFuzzer.class).fuzz();
    }
}
