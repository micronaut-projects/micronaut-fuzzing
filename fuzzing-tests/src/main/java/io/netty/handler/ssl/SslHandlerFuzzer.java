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

@FuzzTarget
public class SslHandlerFuzzer extends HandlerFuzzerBase implements AutoCloseable {
    private static final SelfSignedCertificate CERTIFICATE;

    static {
        try {
            CERTIFICATE = new SelfSignedCertificate();
        } catch (CertificateException e) {
            throw new RuntimeException(e);
        }
    }

    private final SslContext context;

    private static boolean flag(long input, int i) {
        return ((input >>> i) & 1) != 0;
    }

    private SslHandlerFuzzer(FuzzedDataProvider fuzzedDataProvider) throws SSLException {
        byte flags = fuzzedDataProvider.consumeByte();
        SslProvider provider = SslProvider.JDK;
        boolean startTls = flag(flags, 1);
        context = (flag(flags, 5) ? SslContextBuilder.forServer(CERTIFICATE.key(), CERTIFICATE.cert()) : SslContextBuilder.forClient())
                .sslProvider(provider)
                .startTls(startTls)
                .enableOcsp(flag(flags, 2) && provider != SslProvider.JDK)
                .clientAuth(flag(flags, 3) ? ClientAuth.REQUIRE : flag(flags, 4) ? ClientAuth.OPTIONAL : ClientAuth.NONE)
                .build();
        channel.pipeline()
                .addLast(flag(flags, 6) ? context.newHandler(channel.alloc()) : new SslHandler(context.newEngine(channel.alloc()), startTls))
                .addLast(new ErrorHandler());
    }

    public static void fuzzerTestOneInput(FuzzedDataProvider fuzzedDataProvider) throws SSLException {
        SslHandlerFuzzer fuzzer = new SslHandlerFuzzer(fuzzedDataProvider);
        fuzzer.test(fuzzedDataProvider);
        fuzzer.close();
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
