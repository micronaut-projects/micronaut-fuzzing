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
package io.micronaut.fuzzing.bind;

import com.code_intelligence.jazzer.api.FuzzedDataProvider;
import io.micronaut.context.ApplicationContext;
import io.micronaut.context.BeanProvider;
import io.micronaut.core.annotation.Introspected;
import io.micronaut.core.annotation.Nullable;
import io.micronaut.core.bind.ArgumentBinder;
import io.micronaut.core.bind.BeanPropertyBinder;
import io.micronaut.core.convert.ArgumentConversionContext;
import io.micronaut.core.convert.ConversionContext;
import io.micronaut.core.convert.ConversionError;
import io.micronaut.core.convert.exceptions.ConversionErrorException;
import io.micronaut.core.type.Argument;
import io.micronaut.fuzzing.Dict;
import io.micronaut.fuzzing.FuzzTarget;
import io.micronaut.fuzzing.runner.LocalJazzerRunner;
import io.micronaut.json.JsonConfiguration;
import io.micronaut.json.JsonMapper;
import io.micronaut.json.bind.JsonBeanPropertyBinderExceptionHandler;

import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;


@FuzzTarget
@Dict({
    "name=", "age=", "value=", "email=", "id=",

    "address.street=", "address.city=", "meta.key=",

    "items[0].", "items[1].", "items[3].", "items[5].", "items[9].", "items[99].",
    "authors[0].name=", "authors[3].name=", "authors[5].name=", "authors[99].name=",
    "tags[0]=", "tags[2]=", "tags[5]=",

    "map[key].value=", "map[foo].bar=",

    "&", ".",
})
public class JsonBeanPropertyBinderTarget {

    private static final BeanPropertyBinder BINDER;

    static {
        ApplicationContext ctx = ApplicationContext.run(Map.of());
        JsonMapper jsonMapper = ctx.getBean(JsonMapper.class);
        JsonConfiguration jsonConfig = ctx.getBean(JsonConfiguration.class);
        BeanProvider<JsonBeanPropertyBinderExceptionHandler> handlers =
            ctx.getBean(Argument.of(BeanProvider.class, JsonBeanPropertyBinderExceptionHandler.class));
        BINDER = new JsonBeanPropertyBinder(jsonMapper, jsonConfig, handlers);
    }

    public static void fuzzerTestOneInput(FuzzedDataProvider data) {
        int entryCount = data.consumeInt(1, 8);
        Map<String, Object> params = new LinkedHashMap<>();
        for (int i = 0; i < entryCount; i++) {
            params.put(buildKey(data), data.consumeString(20));
        }

        int scenario = data.consumeInt(0, 3);
        switch (scenario) {
            case 0 -> bindNewFlat(params);
            case 1 -> bindExistingFlat(params);
            case 2 -> bindNewNested(params);
            case 3 -> bindViaArgumentContext(params);
        }
    }


    private static void bindNewFlat(Map<String, Object> params) {
        try {
            BINDER.bind(FlatBean.class, params.entrySet());
        } catch (ConversionErrorException e) {
            surfaceIfUnexpected(e);
        }
    }

    private static void bindExistingFlat(Map<String, Object> params) {
        try {
            BINDER.bind(new FlatBean(), params.entrySet());
        } catch (ConversionErrorException e) {
            surfaceIfUnexpected(e);
        }
    }

    private static void bindNewNested(Map<String, Object> params) {
        try {
            BINDER.bind(NestedBean.class, params.entrySet());
        } catch (ConversionErrorException e) {
            surfaceIfUnexpected(e);
        }
    }


    @SuppressWarnings("unchecked")
    private static void bindViaArgumentContext(Map<String, Object> params) {
        Argument<NestedBean> arg = Argument.of(NestedBean.class);
        ArgumentConversionContext<Object> ctx =
            (ArgumentConversionContext<Object>) (ArgumentConversionContext<?>) ConversionContext.of(arg);
        Map<CharSequence, Object> charSeqMap = new LinkedHashMap<>(params);
        ArgumentBinder<Object, Map<CharSequence, ? super Object>> binder = BINDER;
        binder.bind(ctx, charSeqMap);
        for (ConversionError error : ctx) {
            surfaceIfUnexpected(error.getCause());
        }
    }


    private static void surfaceIfUnexpected(ConversionErrorException e) {
        surfaceIfUnexpected(e.getCause());
    }

    private static void surfaceIfUnexpected(Throwable cause) {
        if (cause instanceof IndexOutOfBoundsException e) {
            throw e;
        } else if (cause instanceof NullPointerException e) {
            throw e;
        } else if (cause instanceof StackOverflowError e) {
            throw e;
        }
    }



    private static String buildKey(FuzzedDataProvider data) {
        return data.consumeString(30);
    }




    @Introspected
    public static class FlatBean {
        @Nullable private String name;
        @Nullable private Integer age;
        @Nullable private String email;
        @Nullable private Boolean active;

        @Nullable public String getName() { return name; }
        public void setName(@Nullable String name) { this.name = name; }

        @Nullable public Integer getAge() { return age; }
        public void setAge(@Nullable Integer age) { this.age = age; }

        @Nullable public String getEmail() { return email; }
        public void setEmail(@Nullable String email) { this.email = email; }

        @Nullable public Boolean getActive() { return active; }
        public void setActive(@Nullable Boolean active) { this.active = active; }
    }


    @Introspected
    public static class NestedBean {
        @Nullable private List<ItemEntry> items;
        @Nullable private String label;

        @Nullable public List<ItemEntry> getItems() { return items; }
        public void setItems(@Nullable List<ItemEntry> items) { this.items = items; }

        @Nullable public String getLabel() { return label; }
        public void setLabel(@Nullable String label) { this.label = label; }
    }


    @Introspected
    public static class ItemEntry {
        @Nullable private String value;
        @Nullable private Integer count;

        @Nullable public String getValue() { return value; }
        public void setValue(@Nullable String value) { this.value = value; }

        @Nullable public Integer getCount() { return count; }
        public void setCount(@Nullable Integer count) { this.count = count; }
    }

    public static void main(String[] args) {
        LocalJazzerRunner.create(JsonBeanPropertyBinderTarget.class).fuzz();
    }
}
