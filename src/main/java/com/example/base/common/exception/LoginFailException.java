package com.example.base.common.exception;

import com.example.base.common.response.Status;

public class LoginFailException extends BizException {
  public LoginFailException() {
    super(Status.LOGIN_FAIL);
  }
}
