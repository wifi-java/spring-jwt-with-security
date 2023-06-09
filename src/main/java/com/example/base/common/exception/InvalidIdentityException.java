package com.example.base.common.exception;

import com.example.base.common.response.Status;

/**
 * 아이디 밸리데이션을 통과하지 못했을때 예외 발생
 */
public class InvalidIdentityException extends BizException {
  public InvalidIdentityException() {
    super(Status.INVALID_ID);
  }
}
