package com.example.base.common.exception;

import com.example.base.common.response.Status;

public class AccountLockException extends BizException {
  public AccountLockException() {
    super(Status.ACCOUNT_LOCK);
  }
}
