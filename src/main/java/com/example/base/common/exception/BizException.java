package com.example.base.common.exception;

import com.example.base.common.response.Status;

public class BizException extends RuntimeException {
  private final Status status;

  public BizException(Status status) {
    super(status.getMessage());
    this.status = status;
  }

  public BizException(Status status, String message) {
    super(message);
    this.status = status;
  }

  public Status getStatus() {
    return status;
  }
}
