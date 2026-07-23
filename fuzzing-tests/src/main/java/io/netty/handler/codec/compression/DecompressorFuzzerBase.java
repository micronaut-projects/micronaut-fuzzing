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
package io.netty.handler.codec.compression;

import io.netty.handler.HandlerFuzzerBase;

abstract class DecompressorFuzzerBase extends HandlerFuzzerBase {
    DecompressorFuzzerBase() {
        outputCpuTime = inputCpuTime;
        exceptionCpuTime = 400_000;
    }

    @Override
    protected void onException(Exception e) {
        if (e instanceof DecompressionException) {
            return;
        }
        super.onException(e);
    }
}
