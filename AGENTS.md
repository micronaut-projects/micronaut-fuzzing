# Agent instructions for micronaut-fuzzing

## Repository layout

- `fuzzing-api`: annotations for fuzz targets (`@FuzzTarget`, `@Dict`, `@DictResource`, `@HttpDict`).
- `fuzzing-annotation-processor`: generates the fuzz target metadata from those annotations.
- `fuzzing-runner`: `LocalJazzerRunner` for running a target from an IDE.
- `fuzzing-tests`: the fuzz targets themselves, for Micronaut (`io.micronaut.fuzzing.*`) and Netty (`io.netty.*`).
- `jazzer-plugin`: included Gradle build with the `jazzer`, regression and `prepareClusterFuzz` tasks.
- `oss-fuzz/`: build scripts used by the OSS-Fuzz project.

The default branch is `0.2.x`. The build needs JDK 25 and uses `--enable-preview`.

The build compiles against a source checkout of micronaut-core (`checkouts/micronaut-core`), branch `5.3.x` (see `settings.gradle.kts`). OSS-Fuzz builds against the default branch of micronaut-core and passes it in `OSSFUZZ_MICRONAUT_BRANCH`. Keep the branch in `settings.gradle.kts` the same as micronaut-core's default branch, so that CI catches what would break the OSS-Fuzz build. Targets that use Micronaut internals can break when that branch changes its internal API.

## Writing a Netty fuzz target

- Put the target in the package of the Netty class under test (e.g. `io.netty.handler.codec.redis`), so it can use package-private API.
- Extend `EmbeddedChannelFuzzerBase` (`HandlerFuzzerBase` for inbound handlers). Override `isOutbound()` to fuzz encoders. For the direct `Decompressor` API, extend `AbstractDirectDecompressorFuzzer` or `AbstractDecompressorComparisonFuzzer`.
- A target that does not extend one of these base classes must install the ByteBuf sanitizer itself, with `static { SanitizerTransformer.installLocally(); }`. Referencing `EmbeddedChannelFuzzerBase.SEPARATOR` does not run the static initializer of the base class, because it is a compile-time constant. Such a target should also limit the CPU time per input like `EmbeddedChannelFuzzerBase` does, or explain in its Javadoc why it does not need to.
- The sanitizer gives pooled heap buffers a guard array from `ByteBuf.array()`, and only redirects array accesses in instrumented code to the real array. Code that is not instrumented (the JDK, `io.netty.buffer`, native methods) would read and write the guard array. If code under test passes `buf.array()` to such code in a way the sanitizer does not handle yet, fix it in the sanitizer (`io.micronaut.fuzzing.sanitizer`), not in the target.
- Read the configuration from the `FuzzedDataProvider` in the constructor and store the values. Create the handlers, and any stateful helpers such as checksums, in `setUp()`. When an input exceeds the CPU limit, the base class retries it and calls `setUp()` again, so a handler that is not `@Sharable` must not be reused.
- Do not create heavyweight objects per input if they register global or thread-local state, such as pooled allocators. Create them once and keep them in a static field.
- Annotate the class with `@FuzzTarget`, and add a `@Dict`/`@DictResource` with tokens of the input format. Only use `@HttpDict` when the input is HTTP.
- Add `public static void fuzzerTestOneInput(FuzzedDataProvider)`, which must not declare checked exceptions, and a `main` method that calls `LocalJazzerRunner.create(...).fuzz()`.
- Keep the input as unstructured as possible. Feed the raw input bytes to the code under test instead of building a well-formed message from fuzzed fields. For example, take the whole text of an HTTP message from the input rather than assembling a request line and headers. A generator that only produces well-formed input misses the bugs that need the structure to be broken. Use the `FuzzedDataProvider` for configuration, and dictionaries to teach the fuzzer the tokens of the format.
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

Every new target needs a JUnit smoke test in `fuzzing-tests/src/test/java`. It should use `CannedFuzzedDataProvider` and cover the main code paths. SonarCloud reports coverage on new code, but don't add complexity just to raise it.

- Netty smoke tests must be excluded from the `test` task and included in the `nettyFuzzerTest` task in `fuzzing-tests/build.gradle.kts`. That task runs each test class in its own JVM with the leak detector and without JaCoCo, which conflicts with the sanitizer.
- If the target creates its handlers in `setUp()`, add a test that calls `test()` twice on the same instance, which is what happens on a CPU limit retry.

## Build files

- The `targets` list of the `jazzer` task in `fuzzing-tests/build.gradle.kts` is for local runs and stays commented out. Add new targets as commented-out entries. OSS-Fuzz finds targets through `@FuzzTarget`.
- To reproduce an OSS-Fuzz finding, add a `JazzerRegressionTask` with the base64-encoded input and make `check` depend on it (see `lz4FrameDecoderRegression`).

## Before handing off changes

1. Run the checks:
   ```
   ./gradlew :micronaut-fuzzing-tests:compileJava :micronaut-fuzzing-tests:nettyFuzzerTest :micronaut-fuzzing-tests:spotlessCheck :micronaut-fuzzing-tests:checkstyleMain
   ```
2. Fuzz the new target for a few minutes: temporarily uncomment it in the `jazzer` targets list, run `./gradlew :micronaut-fuzzing-tests:jazzer`, and revert the list afterwards. Fix false positives before handing off the change.
3. Every source file needs the license header (see `config/HEADER`).

## Bugs found in upstream projects

When a target finds a bug in Netty, Micronaut or another library:

1. Check whether it is already fixed or reported: look at the current branch, open issues and PRs, and the repository's security advisories.
2. Decide whether it is security relevant, e.g. a crash, excessive memory or CPU use, or a leak that an attacker can trigger. Security issues must only be reported privately, through a GitHub security advisory, never in a public issue or PR.
3. Report your findings to the user, with a reproducer and, if possible, a fix. The user decides how to report the bug. For Netty fixes, use the `4.2` branch, the Motivation/Modification/Result commit message format, and end the description with "Discovered by fuzzing." Netty PRs get the `found by fuzzing` label.

Do not open PRs, issues or security advisories, here or upstream, unless the user asks you to.
