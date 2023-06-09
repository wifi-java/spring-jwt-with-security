package com.example.base.common.exception;

import com.example.base.common.response.Status;

public class AccountDormancyException extends BizException {
  public AccountDormancyException() {
    super(Status.ACCOUNT_DORMANCY);
  }
}
