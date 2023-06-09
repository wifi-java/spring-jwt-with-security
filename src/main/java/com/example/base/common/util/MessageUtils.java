package com.example.base.common.util;

import org.springframework.context.NoSuchMessageException;
import org.springframework.context.support.MessageSourceAccessor;

public class MessageUtils {

  /**
   * 전달된 코드의 메시지를 다국어 적용하여 반환.
   * 해당하는 메시지가 정의되어 있지 않으면, 코드 그대로 반환.
   *
   * @param code 메시지 코드
   * @return String 다국어 적용된 메시지
   */
  public static String getMessage(String code) {

    return getMessage(code, null);
  }

  /**
   * 전달된 코드의 메시지를 다국어 적용하여 반환.
   * 해당하는 메시지가 정의되어 있지 않으면, 코드 그대로 반환.
   *
   * @param code 메시지 코드
   * @param args placeholder 인자
   * @return String 다국어 적용된 메시지
   */
  public static String getMessage(String code, String[] args) {

    MessageSourceAccessor messageSourceAccessor = ApplicationContextUtils.getBean(
      MessageSourceAccessor.class);
    try {
      return messageSourceAccessor.getMessage(code, args);
    } catch (NoSuchMessageException noSuchMessageException) {
      return code;
    }
  }
}
