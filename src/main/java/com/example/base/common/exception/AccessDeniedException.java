package com.example.base.common.exception;

import com.example.base.common.response.Status;

/**
 * 접근 권한이 없을때 예외 발생
 */
public class AccessDeniedException extends BizException {
  public AccessDeniedException() {
    super(Status.ACCESS_DENIED);
  }

  public AccessDeniedException(Status status) {
      super(status);
    }
}
