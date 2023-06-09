package com.example.base.common.exception;

import com.example.base.common.response.Status;

/**
 * 회원가입중 오류가 발생하여 예외 발생
 */
public class SignUpException extends BizException {
  public SignUpException() {
    super(Status.SIGN_UP_FAIL);
  }
}
