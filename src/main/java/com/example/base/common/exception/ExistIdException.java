package com.example.base.common.exception;

import com.example.base.common.response.Status;

/**
 * 사용중인 아이디가 있을때 예외 발생
 */
public class ExistIdException extends BizException {
  public ExistIdException() {
    super(Status.EXIST_ID);
  }
}
