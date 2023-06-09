package com.example.base.common.exception;

import com.example.base.common.response.Status;

/**
 * 인증 실패했을때 예외 발생
 */
public class AuthenticationFailException extends BizException {
  public AuthenticationFailException() {
    super(Status.AUTHENTICATION_FAIL);
  }

  public AuthenticationFailException(Status status) {
      super(status);
    }
}
