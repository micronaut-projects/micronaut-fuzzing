package io.netty.handler.codec.compression;

import io.netty.handler.HandlerFuzzerBase;

abstract class DecompressorFuzzerBase extends HandlerFuzzerBase {
    DecompressorFuzzerBase() {
        outputCpuTime = inputCpuTime;
    }

    @Override
    protected void onException(Exception e) {
        if (e instanceof DecompressionException) {
            return;
        }
        super.onException(e);
    }
}
