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
import io.netty.handler.ssl.util.SelfSignedCertificate;
import io.netty.util.ReferenceCountUtil;

import javax.net.ssl.SSLException;
import java.security.cert.CertificateException;

/**
 * Fuzz target for Netty's SSL handler.
 */
@FuzzTarget
public final class SslHandlerFuzzer extends HandlerFuzzerBase implements AutoCloseable {
    private static final SelfSignedCertificate CERTIFICATE;

    static {
        try {
            CERTIFICATE = new SelfSignedCertificate();
        } catch (CertificateException e) {
            throw new RuntimeException(e);
        }
    }

    private final byte flags;
    private SslContext context;

    private SslHandlerFuzzer(byte flags) {
        this.flags = flags;
    }

    @Override
    protected EmbeddedChannel setUp() {
        EmbeddedChannel channel = new EmbeddedChannel();
        SslProvider provider = SslProvider.JDK;
        boolean startTls = flag(flags, 1);
        try {
            context = (flag(flags, 5) ? SslContextBuilder.forServer(CERTIFICATE.key(), CERTIFICATE.cert()) : SslContextBuilder.forClient())
                .sslProvider(provider)
                .startTls(startTls)
                .enableOcsp(flag(flags, 2) && provider != SslProvider.JDK)
                .clientAuth(flag(flags, 3) ? ClientAuth.REQUIRE : flag(flags, 4) ? ClientAuth.OPTIONAL : ClientAuth.NONE)
                .build();
        } catch (SSLException e) {
            throw new RuntimeException(e);
        }
        channel.pipeline()
            .addLast(flag(flags, 6) ? context.newHandler(channel.alloc()) : new SslHandler(context.newEngine(channel.alloc()), startTls))
            .addLast(new ErrorHandler());
        return channel;
    }

    private static boolean flag(long input, int i) {
        return ((input >>> i) & 1) != 0;
    }

    public static void fuzzerTestOneInput(FuzzedDataProvider fuzzedDataProvider) {
        byte flags = fuzzedDataProvider.consumeByte();
        new SslHandlerFuzzer(flags).test(fuzzedDataProvider);
    }

    public static void main(String[] args) {
        LocalJazzerRunner.create(SslHandlerFuzzer.class).fuzz();
    }

    @Override
    public void close() {
        ReferenceCountUtil.release(context);
    }

    @ChannelHandler.Sharable
    private static final class ErrorHandler extends ChannelInboundHandlerAdapter {
        @Override
        public void exceptionCaught(ChannelHandlerContext ctx, Throwable cause) throws Exception {
            if (cause instanceof DecoderException && cause.getCause() instanceof SSLException) {
                return;
            }
            super.exceptionCaught(ctx, cause);
        }
    }
}
