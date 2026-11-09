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
package io.netty.handler.codec.http;

import com.code_intelligence.jazzer.api.FuzzedDataProvider;
import io.micronaut.fuzzing.FuzzTarget;
import io.micronaut.fuzzing.HttpDict;
import io.micronaut.fuzzing.runner.LocalJazzerRunner;
import io.netty.channel.ChannelHandlerContext;
import io.netty.channel.ChannelInboundHandlerAdapter;
import io.netty.channel.embedded.EmbeddedChannel;
import io.netty.handler.HandlerFuzzerBase;
import io.netty.handler.codec.http2.DefaultHttp2HeadersDecoder;
import io.netty.handler.codec.http2.Http2ClientUpgradeCodec;
import io.netty.handler.codec.http2.Http2Exception;
import io.netty.handler.codec.http2.Http2FrameCodecBuilder;
import io.netty.handler.codec.http2.Http2FrameStreamException;

import java.util.Set;

/**
 * Fuzzing support type.
 */
@FuzzTarget
@HttpDict
public class HttpClientUpgradeHandlerFuzzer extends HandlerFuzzerBase {
    private static final String HTTP2_PACKAGE = "io.netty.handler.codec.http2.";

    /**
     * The methods (as {@code class#method}) that convert an {@link IllegalArgumentException} from
     * HTTP/2 validation code into an {@link Http2Exception}. See
     * {@link #isWrappedValidationError(Throwable, Throwable)}.
     */
    private static final Set<String> VALIDATION_WRAPPING_SITES = Set.of(
        HTTP2_PACKAGE + "DefaultHttp2FrameReader#readSettingsFrame",
        HTTP2_PACKAGE + "DefaultHttp2HeadersDecoder#decodeHeaders",
        HTTP2_PACKAGE + "HpackDecoder$Http2HeadersSink#appendToHeaderList"
    );

    @Override
    protected EmbeddedChannel setUp() {
        EmbeddedChannel channel = new EmbeddedChannel();
        HttpClientCodec clientCodec = new HttpClientCodec();
        channel.pipeline()
            .addLast(clientCodec)
            .addLast(new HttpClientUpgradeHandler(clientCodec, new Http2ClientUpgradeCodec(Http2FrameCodecBuilder.forClient().build()), 1024))
            .addLast(new ChannelInboundHandlerAdapter() {
                @Override
                public void exceptionCaught(ChannelHandlerContext ctx, Throwable cause) throws Exception {
                    if (isExpected(cause)) {
                        return;
                    }
                    super.exceptionCaught(ctx, cause);
                }
            });

        channel.writeOutbound(new DefaultFullHttpRequest(HttpVersion.HTTP_1_1, HttpMethod.GET, "/", channel.alloc().buffer()));
        return channel;
    }

    @Override
    protected void onException(Exception e) {
        if (isExpected(e)) {
            return;
        }
        super.onException(e);
    }

    static boolean isExpected(Throwable cause) {
        if (cause instanceof Http2Exception) {
            // HTTP/2 protocol errors after the upgrade. An Http2Exception that wraps another
            // exception may hide a bug, so only accept those whose causes are all Http2Exceptions,
            // except for the validation errors accepted by isWrappedValidationError.
            return isHttp2ProtocolError(cause);
        }
        if (cause instanceof Http2FrameStreamException) {
            return isHttp2ProtocolError(cause.getCause());
        }
        if (cause instanceof TooLongHttpContentException) {
            // The 101 response is aggregated with the configured maxContentLength.
            return isThrownBy(cause, HttpObjectAggregator.class, "handleOversizedMessage");
        }
        if (cause.getClass() == IllegalStateException.class) {
            // "Read HTTP response without requesting protocol switch" and
            // "Switching Protocols response with unexpected UPGRADE protocol"
            return isThrownBy(cause, HttpClientUpgradeHandler.class, "decode");
        }
        return false;
    }

    private static boolean isHttp2ProtocolError(Throwable cause) {
        for (Throwable t = cause; t != null; t = t.getCause()) {
            if (!(t instanceof Http2Exception)) {
                return false;
            }
            Throwable next = t.getCause();
            if (next != null && !(next instanceof Http2Exception)) {
                return isWrappedValidationError(t, next);
            }
        }
        return cause != null;
    }

    /**
     * Netty validates some parts of the input with code that throws an
     * {@link IllegalArgumentException}, and converts that exception to an HTTP/2 error in a few
     * places of the read path:
     *
     * <ul>
     *     <li>{@code DefaultHttp2FrameReader.readSettingsFrame}: {@code Http2Settings} rejects an
     *     invalid setting value (PROTOCOL_ERROR or FLOW_CONTROL_ERROR, RFC 9113 section 6.5.2).</li>
     *     <li>{@link DefaultHttp2HeadersDecoder#decodeHeaders}: {@code HpackDecoder} rejects an
     *     invalid header block, e.g. a string literal that is longer than the rest of the block
     *     (COMPRESSION_ERROR).</li>
     *     <li>{@code HpackDecoder.Http2HeadersSink.appendToHeaderList}: header validation fails
     *     (PROTOCOL_ERROR stream error).</li>
     * </ul>
     *
     * <p>Such an {@link Http2Exception} is accepted only if all of these hold:
     *
     * <ul>
     *     <li>The cause is exactly an {@link IllegalArgumentException} without a cause of its own.
     *     Any other type (e.g. {@link NullPointerException},
     *     {@link IndexOutOfBoundsException}, {@link IllegalStateException},
     *     {@link ClassCastException}) is a bug.</li>
     *     <li>The cause was thrown by a class of the {@code io.netty.handler.codec.http2} package,
     *     i.e. by Netty's HTTP/2 validation code. An {@link IllegalArgumentException} from the JDK,
     *     {@code io.netty.buffer} or {@code io.netty.util} is a bug.</li>
     *     <li>The {@link Http2Exception} was created by one of the methods listed above.</li>
     * </ul>
     */
    private static boolean isWrappedValidationError(Throwable http2Exception, Throwable cause) {
        StackTraceElement[] causeTrace = cause.getStackTrace();
        return cause.getClass() == IllegalArgumentException.class
            && cause.getCause() == null
            && causeTrace.length > 0
            && isHttp2CodecClass(causeTrace[0].getClassName())
            && firstFrameOutside(http2Exception, Http2Exception.class.getName()) instanceof StackTraceElement e
            && VALIDATION_WRAPPING_SITES.contains(e.getClassName() + '#' + e.getMethodName());
    }

    private static boolean isHttp2CodecClass(String className) {
        return className.startsWith(HTTP2_PACKAGE)
            && className.indexOf('.', HTTP2_PACKAGE.length()) == -1;
    }

    private static StackTraceElement firstFrameOutside(Throwable cause, String className) {
        for (StackTraceElement e : cause.getStackTrace()) {
            if (!e.getClassName().equals(className)) {
                return e;
            }
        }
        return null;
    }

    private static boolean isThrownBy(Throwable cause, Class<?> type, String method) {
        StackTraceElement[] trace = cause.getStackTrace();
        return trace.length > 0
            && trace[0].getClassName().equals(type.getName())
            && trace[0].getMethodName().equals(method);
    }

    public static void fuzzerTestOneInput(FuzzedDataProvider fuzzedDataProvider) {
        new HttpClientUpgradeHandlerFuzzer().test(fuzzedDataProvider);
    }

    public static void main(String[] args) {
        LocalJazzerRunner.create(HttpClientUpgradeHandlerFuzzer.class).fuzz();
    }
}
