package com.example.base.common.exception;

/**
 * 스프링 시큐리티에서 인증 실패했을때 예외 발생
 */
public class AuthenticationException extends org.springframework.security.core.AuthenticationException {
  public AuthenticationException(String msg, Throwable cause) {
    super(msg, cause);
  }

  public AuthenticationException(String msg) {
    super(msg);
  }
}
