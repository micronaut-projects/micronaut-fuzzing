package io.micronaut.fuzzing;

import com.code_intelligence.jazzer.api.FuzzedDataProvider;
import io.micronaut.fuzzing.util.ByteSplitter;
import io.netty.buffer.ByteBuf;
import io.netty.buffer.ByteBufHolder;
import io.netty.channel.ChannelHandlerContext;
import io.netty.channel.ChannelInboundHandlerAdapter;
import io.netty.channel.embedded.EmbeddedChannel;
import io.netty.util.LeakPresenceDetector;
import io.netty.util.ReferenceCountUtil;
import io.netty.util.concurrent.FastThreadLocalThread;
import io.netty.util.internal.PlatformDependent;
import jdk.jfr.Enabled;
import jdk.jfr.Event;
import jdk.jfr.StackTrace;

@Dict(EmbeddedChannelFuzzerBase.SEPARATOR)
public abstract class EmbeddedChannelFuzzerBase {
    private static final long CPU_TIME_FACTOR = 1024;

    static final String SEPARATOR = "SEP";
    static final ByteSplitter SPLITTER = ByteSplitter.create(SEPARATOR);

    protected final EmbeddedChannel channel;

    protected long baseCpuTime = 500000;
    protected long inputCpuTime = 20;
    protected long outputCpuTime = 0;
    protected boolean hasOutput = false;

    private long outputBytes;

    private boolean finished = false;

    protected EmbeddedChannelFuzzerBase(EmbeddedChannel channel) {
        this.channel = channel;
    }

    public final void test(FuzzedDataProvider provider) {
        FastThreadLocalThread.runWithFastThreadLocal(() -> test0(provider));
    }

    protected void onException(Exception e) {
        PlatformDependent.throwException(e);
    }

    private void test0(FuzzedDataProvider provider) {
        if (!finished) {
            finished = true;
            if (hasOutput) {
                channel.pipeline().addLast(new ChannelInboundHandlerAdapter() {
                    @Override
                    public void channelRead(ChannelHandlerContext ctx, Object msg) {
                        if (outputCpuTime != 0) {
                            long length;
                            if (msg instanceof ByteBuf bb) {
                                length = bb.readableBytes();
                            } else if (msg instanceof ByteBufHolder bbh) {
                                length = bbh.content().readableBytes();
                            } else {
                                length = 0;
                            }
                            if (length != 0) {
                                outputBytes += length;
                            }
                        }

                        // to avoid OOM from output buffering, release inputs immediately
                        ReferenceCountUtil.release(msg);
                    }
                });
            }
        }

        byte[] allBytes = provider.consumeRemainingAsBytes();
        long cpuTimeBudget = baseCpuTime + allBytes.length * inputCpuTime;

        ByteSplitter.ChunkIterator itr = SPLITTER.splitIterator(allBytes);
        long start = CpuTimer.currentThreadCpuTimeNanos();
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
            channel.finish();
        } catch (Exception e) {
            onException(e);
        }
        channel.releaseOutbound();

        long end = CpuTimer.currentThreadCpuTimeNanos();
        cpuTimeBudget += outputBytes * outputCpuTime;

        LeakPresenceDetector.check();
        FlagAppender.checkTriggered();
        long actualTime = end - start;

        CpuTimeSample sample = new CpuTimeSample();
        if (sample.isEnabled()) {
            sample.factor = CPU_TIME_FACTOR;
            sample.baseCpuTime = baseCpuTime;
            sample.inputCpuTime = inputCpuTime;
            sample.outputCpuTime = outputCpuTime;
            sample.inputSize = allBytes.length;
            sample.outputSize = outputBytes;
            sample.actualTime = actualTime;
            sample.commit();
        }

        if (actualTime > CPU_TIME_FACTOR * cpuTimeBudget) {
            throw new RuntimeException("CPU limit triggered. in=" + allBytes.length + " out=" + outputBytes + " actual=" + actualTime);
        }
    }

    @Enabled(false)
    @StackTrace(false)
    static final class CpuTimeSample extends Event {
        long factor;
        long baseCpuTime;
        long inputCpuTime;
        long outputCpuTime;
        int inputSize;
        long outputSize;
        long actualTime;
    }
}
