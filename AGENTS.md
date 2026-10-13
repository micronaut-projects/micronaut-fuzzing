# Agent instructions for micronaut-fuzzing

## Repository layout

- `fuzzing-api`: annotations for fuzz targets (`@FuzzTarget`, `@Dict`, `@DictResource`, `@HttpDict`).
- `fuzzing-annotation-processor`: generates the fuzz target metadata from those annotations.
- `fuzzing-runner`: `LocalJazzerRunner` for running a target from an IDE.
- `fuzzing-tests`: the fuzz targets themselves, for Micronaut (`io.micronaut.fuzzing.*`) and Netty (`io.netty.*`).
- `jazzer-plugin`: included Gradle build with the `jazzer`, regression and `prepareClusterFuzz` tasks.
- `oss-fuzz/`: build scripts used by the OSS-Fuzz project.

The default branch is `0.2.x`. The build needs JDK 25 and uses `--enable-preview`.

The build compiles against a source checkout of micronaut-core (`checkouts/micronaut-core`), branch `5.2.x` by default. The OSS-Fuzz build sets `OSSFUZZ_MICRONAUT_BRANCH=5.3.x`. When you use Micronaut internals, make sure the code compiles against both:

```
./gradlew :micronaut-fuzzing-tests:compileJava
OSSFUZZ_MICRONAUT_BRANCH=5.3.x ./gradlew :micronaut-fuzzing-tests:compileJava
```

## Writing a Netty fuzz target

- Put the target in the package of the Netty class under test (e.g. `io.netty.handler.codec.redis`), so it can use package-private API.
- Extend `EmbeddedChannelFuzzerBase` (`HandlerFuzzerBase` for inbound handlers). Override `isOutbound()` to fuzz encoders. For the direct `Decompressor` API, extend `AbstractDirectDecompressorFuzzer` or `AbstractDecompressorComparisonFuzzer`.
- Read the configuration from the `FuzzedDataProvider` in the constructor and store the values. Create the handlers, and any stateful helpers such as checksums, in `setUp()`. When an input exceeds the CPU limit, the base class retries it and calls `setUp()` again, so a handler that is not `@Sharable` must not be reused.
- Do not create heavyweight objects per input if they register global or thread-local state, such as pooled allocators. Create them once and keep them in a static field.
- Annotate the class with `@FuzzTarget`, and add a `@Dict`/`@DictResource` with tokens of the input format. Only use `@HttpDict` when the input is HTTP.
- Add `public static void fuzzerTestOneInput(FuzzedDataProvider)`, which must not declare checked exceptions, and a `main` method that calls `LocalJazzerRunner.create(...).fuzz()`.
- Prefer an oracle over only checking that nothing crashes: compare two implementations (differential), compress and decompress (round trip), or check invariants of the output.

### Exception filtering

The base class reports every exception. Override `onException` only to ignore the exceptions that the code under test throws on purpose for invalid input, and keep the filter as narrow as possible:

- `ByteToMessageDecoder` wraps any exception that is not a `DecoderException` in a `DecoderException`, and `MessageToByteEncoder` does the same with `EncoderException`. Ignoring every `DecoderException` or `EncoderException` therefore hides real bugs. Look at the cause.
- Some codecs wrap unexpected exceptions in their own exception type. `RedisDecoder`, for example, wraps any exception in a `RedisCodecException` with that cause. In that case, only ignore instances without a cause.
- Never ignore `IllegalArgumentException`, `IndexOutOfBoundsException`, `IllegalStateException` or `NullPointerException` in general. They usually indicate a bug.
- If the target finds a real bug in Netty, ignore exactly that case until the fix is released: match the exception type and the method that throws it (via the stack trace). Link the upstream fix in a comment.

### Leaks and logging

- After every input, the base class runs `LeakPresenceDetector.check()`. It also runs `FlagAppender.checkTriggered()`, which fails the input if anything was logged at WARN or above.
- Allocate buffers from `channel.alloc()` or `ByteBufAllocator.DEFAULT`. `Unpooled.wrappedBuffer` and similar buffers are not tracked by the leak detector.
- Do not release buffers that were handed to the pipeline; the pipeline owns them.
- `MessageToByteEncoder.write` leaks its input when `allocateBuffer` throws. Configure encoders so that this cannot happen (see `ZstdEncoderFuzzer`).

## Smoke tests

Every new target needs a JUnit smoke test in `fuzzing-tests/src/test/java`. It should use `CannedFuzzedDataProvider` and cover the main code paths. SonarCloud requires 80% coverage on new code.

- Netty smoke tests must be excluded from the `test` task and included in the `nettyFuzzerTest` task in `fuzzing-tests/build.gradle.kts`. That task runs each test class in its own JVM with the leak detector and without JaCoCo, which conflicts with the sanitizer.
- If the target creates its handlers in `setUp()`, add a test that calls `test()` twice on the same instance, which is what happens on a CPU limit retry.

## Build files

- The `targets` list of the `jazzer` task in `fuzzing-tests/build.gradle.kts` is for local runs and stays commented out. Add new targets as commented-out entries. OSS-Fuzz finds targets through `@FuzzTarget`.
- To reproduce an OSS-Fuzz finding, add a `JazzerRegressionTask` with the base64-encoded input and make `check` depend on it (see `lz4FrameDecoderRegression`).

## Before opening a PR

1. Run the checks:
   ```
   ./gradlew :micronaut-fuzzing-tests:compileJava :micronaut-fuzzing-tests:nettyFuzzerTest :micronaut-fuzzing-tests:spotlessCheck :micronaut-fuzzing-tests:checkstyleMain
   ```
2. Fuzz the new target for a few minutes: temporarily uncomment it in the `jazzer` targets list, run `./gradlew :micronaut-fuzzing-tests:jazzer`, and revert the list afterwards. Fix false positives before opening the PR.
3. Every source file needs the license header (see `config/HEADER`).

## Bugs found in upstream projects

When a target finds a bug in Netty, Micronaut or another library:

1. Check whether it is already fixed or reported: look at the current branch, open issues and PRs, and the repository's security advisories.
2. Decide whether it is security relevant, e.g. a crash, excessive memory or CPU use, or a leak that an attacker can trigger. Report security issues privately through a GitHub security advisory, never in a public issue or PR.
3. Otherwise, open a PR. For Netty, target the `4.2` branch, use the Motivation/Modification/Result commit message format, end the description with "Discovered by fuzzing.", and add the `found by fuzzing` label.
