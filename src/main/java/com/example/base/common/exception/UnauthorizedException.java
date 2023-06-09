package com.example.base.common.exception;

import com.example.base.common.response.Status;

/**
 * 클라이언트가 인증되지 않았거나 유효한 인증 정보가 부족하여 요청이 거부되었을때 예외 발생
 */
public class UnauthorizedException extends BizException {
  public UnauthorizedException() {
    super(Status.UNAUTHORIZED);
  }

  public UnauthorizedException(Status status) {
      super(status);
    }
}
