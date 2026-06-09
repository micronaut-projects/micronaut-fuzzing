/*
 * Copyright 2017-2025 original authors
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
package io.micronaut.fuzzing.http;

import ch.qos.logback.classic.Level;
import ch.qos.logback.classic.LoggerContext;
import com.code_intelligence.jazzer.api.FuzzedDataProvider;
import io.micronaut.context.ApplicationContext;
import io.micronaut.core.convert.ConversionService;
import io.micronaut.fuzzing.Dict;
import io.micronaut.fuzzing.FuzzTarget;
import io.micronaut.fuzzing.runner.LocalJazzerRunner;
import org.slf4j.LoggerFactory;

import java.io.File;
import java.math.BigDecimal;
import java.math.BigInteger;
import java.net.URI;
import java.net.URL;
import java.nio.charset.Charset;
import java.time.Duration;
import java.time.Instant;
import java.time.LocalDate;
import java.time.LocalDateTime;
import java.time.OffsetDateTime;
import java.time.ZonedDateTime;
import java.util.Currency;
import java.util.Locale;
import java.util.UUID;


/**
 * Fuzzing support type.
 */
@FuzzTarget
@Dict({
    "0", "-1", "1",
    "2147483647", "2147483648",
    "-2147483648", "-2147483649",


    "9223372036854775807",
    "9223372036854775808",
    "-9223372036854775808",


    "9999999999999999999",
    "99999999999999999999999999999",


    "NaN", "Infinity", "-Infinity",
    "1e308", "-1e308", "1e999999",
    "-0", "+0", "-0.0", "+0.0",


    "0x1A", "0xFF", "0b1010",
    "123_456",
    "  123  ",


    "true", "false", "TRUE", "FALSE",
    "yes", "no", "Yes", "No", "YES", "NO",
    "on", "off", "1", "0",
    "truE", "FaLsE",


    "2024-01-01", "1970-01-01", "9999-12-31",
    "1970-01-01T00:00:00Z",
    "2024-06-15T10:30:00+02:00",
    "2024-01-01T00:00:00.000000000Z",


    "0000-01-01",
    "2024-02-30",
    "2024-13-01",
    "+999999999-12-31",


    "PT1H", "PT1H30M", "P1D", "P1Y",
    "PT0S", "PT-1S", "PT999999999H",


    "00000000-0000-0000-0000-000000000000",
    "ffffffff-ffff-ffff-ffff-ffffffffffff",
    "not-a-uuid",


    "UTF-8", "ISO-8859-1", "US-ASCII",
    "UTF-16", "windows-1252",
    "nonexistent-charset",


    "http://localhost",
    "file:///etc/passwd",
    "://",
    "http://[::1]",
    "http://user:pass@host:8080/path?q=1#frag",


    "en", "en_US", "zh_Hans_CN",
    "und",


    "USD", "EUR", "JPY", "XXX",


    " ", "\t", "\n", "\r\n",
    "\u0000", "\u0000\u0000\u0000",
    "null", "nil", "undefined",
    "\\", "\"", "'",
})
public class TypeConversionTarget {

    private static final ConversionService APP_CTX_CONVERSION_SERVICE;

    static {
        setLogLevel("io.micronaut", Level.TRACE);
        APP_CTX_CONVERSION_SERVICE = ApplicationContext.run().getBean(ConversionService.class);
        setLogLevel("io.micronaut", Level.WARN);
    }

    private static final Class<?>[] TARGET_TYPES = {
        Integer.class,
        Long.class,
        Short.class,
        Byte.class,
        Float.class,
        Double.class,
        BigDecimal.class,
        BigInteger.class,


        Boolean.class,


        LocalDate.class,
        LocalDateTime.class,
        ZonedDateTime.class,
        OffsetDateTime.class,
        Instant.class,
        Duration.class,


        UUID.class,
        Locale.class,
        Currency.class,
        Charset.class,


        URI.class,
        URL.class,
        File.class,
    };

    private static void setLogLevel(String loggerName, Level level) {
        LoggerContext loggerContext = (LoggerContext) LoggerFactory.getILoggerFactory();
        loggerContext.getLogger(loggerName).setLevel(level);
    }

    public static void fuzzerTestOneInput(FuzzedDataProvider data) {
        int typeIndex = data.consumeInt(0, TARGET_TYPES.length - 1);
        Class<?> targetType = TARGET_TYPES[typeIndex];
        String value = data.consumeRemainingAsString();

        ConversionService.SHARED.convert(value, targetType);
        APP_CTX_CONVERSION_SERVICE.convert(value, targetType);
    }

    public static void main(String[] args) {
        LocalJazzerRunner.create(TypeConversionTarget.class).fuzz();
    }
}
