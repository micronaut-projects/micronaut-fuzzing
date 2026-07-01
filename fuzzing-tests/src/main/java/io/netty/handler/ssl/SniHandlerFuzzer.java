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
import io.netty.handler.HandlerFuzzerBase;
import io.netty.handler.codec.DecoderException;
import io.netty.handler.ssl.util.SelfSignedCertificate;
import io.netty.util.ReferenceCountUtil;

import javax.net.ssl.SSLException;
import java.security.cert.CertificateException;

/**
 * Fuzz target for Netty's SniHandler (CVE-2026-45416 / GHSA-x4gw-5cx5-pgmh).
 *
 * <p>SslClientHelloHandler.decode() reads the 24-bit TLS handshake length and
 * eagerly allocates a buffer of that size when maxClientHelloLength=0 (the default
 * for all SniHandler constructors). Nine crafted bytes are enough to trigger a
 * 16 MiB allocation. This fuzzer exercises that code path so the memory sanitizer
 * can detect abnormal allocation behaviour.
 */
@FuzzTarget
public final class SniHandlerFuzzer extends HandlerFuzzerBase implements AutoCloseable {
    private static final SslContext SERVER_CONTEXT;

    static {
        try {
            SelfSignedCertificate cert = new SelfSignedCertificate();
            SERVER_CONTEXT = SslContextBuilder.forServer(cert.key(), cert.cert())
                .sslProvider(SslProvider.JDK)
                .build();
        } catch (CertificateException | SSLException e) {
            throw new RuntimeException(e);
        }
    }

    private SniHandlerFuzzer(FuzzedDataProvider fuzzedDataProvider) {
        SniHandler sniHandler = new SniHandler(hostname -> SERVER_CONTEXT);
        channel.pipeline()
            .addLast(sniHandler)
            .addLast(new ErrorHandler());
    }

    public static void fuzzerTestOneInput(FuzzedDataProvider fuzzedDataProvider) {
        var fuzzer = new SniHandlerFuzzer(fuzzedDataProvider);
        fuzzer.test(fuzzedDataProvider);
        fuzzer.close();
    }

    public static void main(String[] args) {
        LocalJazzerRunner.create(SniHandlerFuzzer.class).fuzz();
    }

    @Override
    public void close() {
        ReferenceCountUtil.release(SERVER_CONTEXT);
    }

    @ChannelHandler.Sharable
    private static final class ErrorHandler extends ChannelInboundHandlerAdapter {
        @Override
        public void exceptionCaught(ChannelHandlerContext ctx, Throwable cause) throws Exception {
            if (cause instanceof DecoderException && cause.getCause() instanceof SSLException) {
                return;
            }
            if (cause instanceof DecoderException) {
                return;
            }
            super.exceptionCaught(ctx, cause);
        }
    }
}
