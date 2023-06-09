package com.example.base.common.response;

import java.util.ArrayList;
import java.util.List;

import lombok.Getter;
import org.springframework.validation.BindingResult;
import org.springframework.web.method.annotation.MethodArgumentTypeMismatchException;


@Getter
public class ResultData<T> {

  private final int code;
  private final String message;

  private final T data;
  private final List<FieldError> errors;

  private ResultData(Status status, T data, List<FieldError> errors) {
    this.code = status.getCode();
    this.message = status.getMessage();
    this.data = data;
    this.errors = errors;
  }

  public static <T> ResultData of(Status status) {
    return new ResultData(status, null, new ArrayList<>());
  }

  public static <T> ResultData of(Status status, T data) {
    return new ResultData(status, data, new ArrayList<>());
  }

  public static <T> ResultData of(Status status, T data, BindingResult bindingResult) {
    return new ResultData(status, data, FieldError.of(bindingResult));
  }

  public static ResultData of(MethodArgumentTypeMismatchException e) {
    final String value = e.getValue() == null ? "" : e.getValue().toString();
    final List<FieldError> errors = FieldError.of(e.getName(), value, e.getErrorCode());
    return new ResultData(Status.INVALID_TYPE_VALUE, null, errors);
  }

}
