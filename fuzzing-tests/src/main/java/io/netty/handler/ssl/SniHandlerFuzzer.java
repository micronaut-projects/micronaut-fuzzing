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
package io.netty.handler.ssl;

import com.code_intelligence.jazzer.api.FuzzedDataProvider;
import io.micronaut.fuzzing.FuzzTarget;
import io.micronaut.fuzzing.runner.LocalJazzerRunner;
import io.netty.channel.ChannelHandler;
import io.netty.channel.ChannelHandlerContext;
import io.netty.channel.ChannelInboundHandlerAdapter;
import io.netty.channel.embedded.EmbeddedChannel;
import io.netty.handler.HandlerFuzzerBase;
import io.netty.handler.codec.DecoderException;
import io.netty.handler.codec.TooLongFrameException;
import io.netty.handler.ssl.util.SelfSignedCertificate;
import io.netty.util.DomainNameMapping;
import io.netty.util.DomainNameMappingBuilder;

import javax.net.ssl.SSLException;
import java.net.IDN;
import java.security.cert.CertificateException;
import java.text.ParseException;

/**
 * Fuzz target for Netty's SNI handler.
 */
@FuzzTarget
public final class SniHandlerFuzzer extends HandlerFuzzerBase {
    private static final SelfSignedCertificate CERTIFICATE;
    private static final SslContext DEFAULT_CONTEXT;
    private static final SslContext NETTY_CONTEXT;
    private static final DomainNameMapping<SslContext> MAPPING;

    static {
        try {
            CERTIFICATE = new SelfSignedCertificate();
            DEFAULT_CONTEXT = newServerContext();
            NETTY_CONTEXT = newServerContext();
            MAPPING = new DomainNameMappingBuilder<SslContext>(DEFAULT_CONTEXT)
                .add("*.netty.io", NETTY_CONTEXT)
                .add("*.micronaut.io", DEFAULT_CONTEXT)
                .build();
        } catch (CertificateException | SSLException e) {
            throw new RuntimeException(e);
        }
    }

    private final int maxClientHelloLength;

    SniHandlerFuzzer(int maxClientHelloLength) {
        this.maxClientHelloLength = maxClientHelloLength;
    }

    private static SslContext newServerContext() throws SSLException {
        return SslContextBuilder.forServer(CERTIFICATE.key(), CERTIFICATE.cert())
            .sslProvider(SslProvider.JDK)
            .build();
    }

    @Override
    protected EmbeddedChannel setUp() {
        EmbeddedChannel channel = new EmbeddedChannel();
        channel.pipeline()
            .addLast(new SniHandler(MAPPING, maxClientHelloLength, 0))
            .addLast(new ErrorHandler());
        return channel;
    }

    @Override
    protected void onException(Exception e) {
        if (isExpected(e)) {
            return;
        }
        super.onException(e);
    }

    private static boolean isExpected(Throwable cause) {
        if (isInvalidHostName(cause)) {
            return true;
        }
        if (cause instanceof TooLongFrameException ||
            cause instanceof SSLException) {
            return true;
        }
        if (cause instanceof IllegalArgumentException && cause.getCause() instanceof ParseException) {
            return true;
        }
        if (!(cause instanceof DecoderException)) {
            return false;
        }
        Throwable nested = cause.getCause();
        return nested != null && isExpected(nested);
    }

    /**
     * {@link DomainNameMapping} converts a host name with non-ASCII characters (non-ASCII SNI bytes decode to
     * U+FFFD) with {@link IDN#toASCII(String, int)}, which rejects invalid names such as names with an empty label.
     * {@link SniHandler} then fails the handshake with a {@link DecoderException}, before any {@link SslContext}
     * is selected.
     */
    private static boolean isInvalidHostName(Throwable cause) {
        if (cause.getClass() != DecoderException.class
            || !isTopFrame(cause, SniHandler.class.getName(), "onLookupComplete")) {
            return false;
        }
        Throwable nested = cause.getCause();
        if (nested == null || nested.getClass() != IllegalArgumentException.class
            || !isTopFrame(nested, IDN.class.getName(), null)) {
            return false;
        }
        for (StackTraceElement element : nested.getStackTrace()) {
            if (element.getClassName().equals(DomainNameMapping.class.getName())
                && element.getMethodName().equals("normalizeHostname")) {
                return true;
            }
        }
        return false;
    }

    private static boolean isTopFrame(Throwable t, String className, String methodName) {
        StackTraceElement[] trace = t.getStackTrace();
        return trace.length > 0
            && trace[0].getClassName().equals(className)
            && (methodName == null || trace[0].getMethodName().equals(methodName));
    }

    public static void fuzzerTestOneInput(FuzzedDataProvider fuzzedDataProvider) {
        int maxClientHelloLength = fuzzedDataProvider.consumeInt(0, 8192);
        new SniHandlerFuzzer(maxClientHelloLength).test(fuzzedDataProvider);
    }

    public static void main(String[] args) {
        LocalJazzerRunner.create(SniHandlerFuzzer.class).fuzz();
    }

    @ChannelHandler.Sharable
    private static final class ErrorHandler extends ChannelInboundHandlerAdapter {
        @Override
        public void exceptionCaught(ChannelHandlerContext ctx, Throwable cause) throws Exception {
            if (isExpected(cause)) {
                return;
            }
            super.exceptionCaught(ctx, cause);
        }
    }
}
