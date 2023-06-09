package com.example.base.common.strategy;

import com.fasterxml.jackson.databind.PropertyNamingStrategies;

// 써드파티 API 요청시 dto에 키 값을 모두 소문자로 보내야 할 때.
// @JsonNaming(LowerSnakeCaseStrategy.class)
public class LowerSnakeCaseStrategy extends PropertyNamingStrategies.SnakeCaseStrategy {

  @Override
  public String translate(String input) {
    String lowerCase = super.translate(input);
    return lowerCase.toLowerCase();
  }
}
