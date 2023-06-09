package com.example.base.common.exception;

import com.example.base.common.response.Status;

/**
 * 패스워드가 일치하지 않았을때 예외 발생
 */
public class NotSamePasswordException extends BizException {
  public NotSamePasswordException() {
    super(Status.NOT_SAME_PASSWORD);
  }
}
