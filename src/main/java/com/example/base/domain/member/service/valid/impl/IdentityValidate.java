package com.example.base.domain.member.service.valid.impl;

import java.util.regex.Matcher;
import java.util.regex.Pattern;

class IdentityValidate {
  public enum Validate {
    ok, minWordLength // 문자열 길이가 짧음
    , maxWordLength // 문자열 길이가 길음
    , special // 특수문자 포함되어 있음
    , digit // 숫자만 있음
    , hangeul // 한글이 포함되어 있음
  }

  private String value = "";
  private Validate validate = Validate.ok;

  public IdentityValidate(String value) {
    this.value = value;
  }

  public Validate validate() {
    return validate;
  }

  /**
   * 최소 아이디 길이
   *
   * @param length
   */
  public IdentityValidate minLength(int length) {
    if (validate == Validate.ok) {
      if (value.length() < length) {
        validate = Validate.minWordLength;
      }
    }

    return this;
  }

  /**
   * 최대 아이디 길이
   *
   * @param length
   */
  public IdentityValidate maxLength(int length) {
    if (validate == Validate.ok) {
      if (value.length() > length) {
        validate = Validate.maxWordLength;
      }
    }

    return this;
  }


  /**
   * 특수문자 포함 확인
   */
  public IdentityValidate combineSpecial() {
    if (validate == Validate.ok) {
      Pattern pattern = Pattern.compile(special());
      Matcher matcher = pattern.matcher(value);

      if (matcher.find()) {
        validate = Validate.special;
      }
    }

    return this;
  }

  /**
   * 숫자만 있는지 확인
   */
  public IdentityValidate onlyDigit() {
    if (validate == Validate.ok) {
      Pattern pattern = Pattern.compile(digit());
      Matcher matcher = pattern.matcher(value);

      if (matcher.find()) {
        validate = Validate.digit;
      }
    }

    return this;
  }

  /**
   * 한글이 포함되어 있는지 확인
   */
  public IdentityValidate combineHangeul() {
    if (validate == Validate.ok) {
      Pattern pattern = Pattern.compile(hangeulPattern());
      Matcher matcher = pattern.matcher(value);

      if (matcher.find()) {
        validate = Validate.hangeul;
      }
    }

    return this;
  }


  /**
   * 특수문자 확인
   *
   * @return
   */
  private String special() {
    return "[ !@#$%^&*(),.?\\\\\\\":{}|<>]";
  }

  /**
   * 숫자만 있는지 확인
   *
   * @return
   */
  private String digit() {
    return "^[0-9]+$";
  }

  /**
   * 한글 있는지 확인 패턴
   */
  private String hangeulPattern() {
    return "[ㄱ-ㅎ|ㅏ-ㅣ|가-힣]";
  }
}
