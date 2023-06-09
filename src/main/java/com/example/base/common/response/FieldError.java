package com.example.base.common.response;

import java.util.ArrayList;
import java.util.List;
import java.util.stream.Collectors;

import lombok.AllArgsConstructor;
import lombok.Getter;
import lombok.NoArgsConstructor;
import org.springframework.validation.BindingResult;


@Getter
@NoArgsConstructor
@AllArgsConstructor
class FieldError {

  private String field;
  private String value;
  private String reason;

  public static List<FieldError> of(final String field, final String value, final String reason) {
    List<FieldError> fieldErrors = new ArrayList<>();
    fieldErrors.add(new FieldError(field, value, reason));
    return fieldErrors;
  }

  static List<FieldError> of(final BindingResult bindingResult) {
    return bindingResult.getFieldErrors()
            .stream()
            .map(error -> new FieldError(error.getField(),
                    error.getRejectedValue() == null ? "" : error.getRejectedValue()
                            .toString(),
                    error.getDefaultMessage()))
            .collect(Collectors.toList());
  }
}
