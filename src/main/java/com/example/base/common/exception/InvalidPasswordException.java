package com.example.base.common.exception;

import com.example.base.common.response.Status;

/**
 * 패스워드 밸리데이션을 통과하지 못했을때 예외 발생
 */
public class InvalidPasswordException extends BizException {
  public InvalidPasswordException() {
    super(Status.INVALID_PW_ERROR);
  }
}
