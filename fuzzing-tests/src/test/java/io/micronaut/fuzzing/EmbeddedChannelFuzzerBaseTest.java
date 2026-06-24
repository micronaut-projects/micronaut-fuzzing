package io.micronaut.fuzzing;

import com.code_intelligence.jazzer.api.CannedFuzzedDataProvider;
import io.netty.channel.embedded.EmbeddedChannel;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;

import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;

class EmbeddedChannelFuzzerBaseTest {

    @BeforeAll
    static void configureLeakDetector() {
        System.setProperty("io.netty.customResourceLeakDetector", "io.netty.util.LeakPresenceDetector");
        System.setProperty("io.netty.leakDetection.targetRecords", "0");
    }

    @Test
    void doesNotRetryWhenCpuLimitIsNotExceeded() throws Exception {
        CannedFuzzedDataProvider provider = CannedFuzzedDataProvider.create(List.of(new byte[0]));
        TestFuzzer fuzzer = new TestFuzzer(false);
        fuzzer.test(provider);

        assertEquals(1, fuzzer.attempts);
    }

    @Test
    void retriesCpuLimitFailureOnceWithSameInput() throws Exception {
        CannedFuzzedDataProvider provider = CannedFuzzedDataProvider.create(List.of(new byte[] {1, 2, 3}));
        TestFuzzer fuzzer = new TestFuzzer(true);
        fuzzer.test(provider);

        assertEquals(2, fuzzer.attempts);
    }

    private static final class TestFuzzer extends EmbeddedChannelFuzzerBase {
        private final boolean failFirstAttempt;
        private int attempts;

        TestFuzzer(boolean failFirstAttempt) {
            this.failFirstAttempt = failFirstAttempt;
            this.inputCpuTime = 0;
            this.outputCpuTime = 0;
        }

        @Override
        protected EmbeddedChannel setUp() {
            attempts++;
            baseCpuTime = failFirstAttempt && attempts == 1 ? -1 : 1_000_000_000L;
            return new EmbeddedChannel();
        }
    }
}
