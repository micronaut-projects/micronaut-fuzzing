package io.micronaut.fuzzing.http;

import io.micronaut.core.annotation.NonNull;
import io.netty.buffer.ByteBuf;
import io.netty.channel.ChannelHandler;
import io.netty.channel.ChannelHandlerContext;
import io.netty.channel.ChannelInboundHandlerAdapter;
import io.netty.handler.timeout.ReadTimeoutException;

@ChannelHandler.Sharable
final class BlackholeInboundHandler extends ChannelInboundHandlerAdapter {
    static final BlackholeInboundHandler INSTANCE = new BlackholeInboundHandler();

    @Override
    public void channelRead(@NonNull ChannelHandlerContext ctx, @NonNull Object msg) throws Exception {
        if (msg instanceof ByteBuf) {
            // discard
            ((ByteBuf) msg).release();
        } else {
            super.channelRead(ctx, msg);
        }
    }

    @Override
    public void exceptionCaught(ChannelHandlerContext ctx, Throwable cause) throws Exception {
        if (cause instanceof ReadTimeoutException) {
            return;
        }
        super.exceptionCaught(ctx, cause);
    }
}
