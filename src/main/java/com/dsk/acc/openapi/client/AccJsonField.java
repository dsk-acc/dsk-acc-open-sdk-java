package com.dsk.acc.openapi.client;

import java.lang.annotation.Documented;
import java.lang.annotation.ElementType;
import java.lang.annotation.Retention;
import java.lang.annotation.RetentionPolicy;
import java.lang.annotation.Target;

@Documented
@Retention(RetentionPolicy.RUNTIME)
@Target({ElementType.FIELD, ElementType.METHOD})
public @interface AccJsonField {

    /** 命名 */
    String value();

    /** 反序列化字段时字段的可选名称  */
    String[] alternate() default {};
}
