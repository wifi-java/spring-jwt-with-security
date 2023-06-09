package com.example.base.common.strategy;

import com.fasterxml.jackson.databind.PropertyNamingStrategies;


// 써드파티 API 요청시 dto에 키 값을 모두 대문자로 보내야 할 때.
// @JsonNaming(UpperSnakeCaseStrategy.class)
public class UpperSnakeCaseStrategy extends PropertyNamingStrategies.SnakeCaseStrategy {

  @Override
  public String translate(String input) {
    String upperCase = super.translate(input);
    return upperCase.toUpperCase();
  }
}
