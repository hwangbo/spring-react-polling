package com.lilbear.security;

import org.springframework.security.core.annotation.AuthenticationPrincipal;

import java.lang.annotation.*;

/*
    Spring Security 의 의존성을 줄이기 위해 생성
    만약 Spring Security 를 제거해야 한다면, 이 어노테이션을 변경하여 쉽게 제거 가능
 */
@Target({ElementType.PARAMETER, ElementType.TYPE})
@Retention(RetentionPolicy.RUNTIME)
@Documented
@AuthenticationPrincipal
public @interface CurrentUser {
}
