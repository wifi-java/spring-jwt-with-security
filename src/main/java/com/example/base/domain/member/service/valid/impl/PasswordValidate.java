package com.example.base.domain.member.service.valid.impl;

import java.util.regex.Matcher;
import java.util.regex.Pattern;

class PasswordValidate {
  public enum Validate {
    ok, minWordLength // 문자열 길이가 짧음
    , maxWordLength // 문자열 길이가 길음
    , consecutiveDigit // 연속된 숫자 존재
    , consecutiveWord // 연속된 문자 존재
    , repeatWordOrDigit // 같은 숫자 또는 문자가 반복 됨
    , notDigitAndWordAndSpecial // 숫자 문자 특수문자 조합이 아님
    , upperLower // 대소문자 조합이 아님
    , contains // 특정 문자열이 존재
    , hangeul // 한글이 포함되어 있음
  }

  private String value = "";
  private Validate validate = Validate.ok;

  public PasswordValidate(String value) {
    this.value = value;
  }

  public Validate validate() {
    return validate;
  }

  /**
   * 최소 패스워드 길이
   *
   * @param length
   */
  public PasswordValidate minLength(int length) {
    if (validate == Validate.ok) {
      if (value.length() < length) {
        validate = Validate.minWordLength;
      }
    }

    return this;
  }

  /**
   * 최대 패스워드 길이
   *
   * @param length
   */
  public PasswordValidate maxLength(int length) {
    if (validate == Validate.ok) {
      if (value.length() > length) {
        validate = Validate.maxWordLength;
      }
    }

    return this;
  }


  /**
   * 연속된 숫자 체크
   *
   * @param length (몇자리까지 체크할지)
   */
  public PasswordValidate consecutiveDigit(int length) {
    if (validate == Validate.ok) {
      Pattern pattern = Pattern.compile(getDigit(length));
      Matcher matcher = pattern.matcher(value);

      if (!matcher.find()) {
        pattern = Pattern.compile(getDigitReverse(length));
        matcher = pattern.matcher(value);

        if (matcher.find()) {
          validate = Validate.consecutiveDigit;
        }
      } else {
        validate = Validate.consecutiveDigit;
      }
    }

    return this;
  }

  /**
   * 연속된 문자 체크
   *
   * @param length (몇자리까지 체크할지)
   */
  public PasswordValidate consecutiveWord(int length) {
    if (validate == Validate.ok) {
      Pattern pattern = Pattern.compile(getAlphabet(length));
      Matcher matcher = pattern.matcher(value);

      if (!matcher.find()) {
        pattern = Pattern.compile(getAlphabetReverse(length));
        matcher = pattern.matcher(value);

        if (matcher.find()) {
          validate = Validate.consecutiveWord;
        }
      } else {
        validate = Validate.consecutiveWord;
      }
    }

    return this;
  }

  /**
   * 같은 숫자 또는 문자가 반복되는지 확인
   *
   * @param length (몇자리까지 체크할지)
   */
  public PasswordValidate repeatWordOrDigit(int length) {
    if (validate == Validate.ok) {
      Pattern pattern = Pattern.compile(repeatWord(length));
      Matcher matcher = pattern.matcher(value);

      if (matcher.find()) {
        validate = Validate.repeatWordOrDigit;
      }
    }

    return this;
  }

  /**
   * 숫자, 영어, 특수문자 조합 확인
   */
  public PasswordValidate combineDigitAndWordAndSpecial() {
    if (validate == Validate.ok) {
      Pattern pattern = Pattern.compile(digitAndWordAndSpecial());
      Matcher matcher = pattern.matcher(value);

      if (!matcher.find()) {
        validate = Validate.notDigitAndWordAndSpecial;
      }
    }

    return this;
  }

  /**
   * 대소문자 조합 확인
   */
  public PasswordValidate combineWordUpperLower() {
    if (validate == Validate.ok) {
      Pattern pattern = Pattern.compile(upperAndLower());
      Matcher matcher = pattern.matcher(value);

      if (!matcher.find()) {
        validate = Validate.upperLower;
      }
    }

    return this;
  }

  /**
   * 한글이 포함되어 있는지 확인
   */
  public PasswordValidate combineHangeul() {
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
   * 특정 문자열이 있는지 확인
   */
  public PasswordValidate contains(String word) {
    if (validate == Validate.ok) {
      boolean isContains = value.contains(word);

      if (isContains) {
        validate = Validate.contains;
      }
    }

    return this;
  }

  /**
   * 같은 숫자 또는 문자가 반복되는지 확인
   *
   * @param length
   * @return
   */
  private String repeatWord(int length) {
    StringBuilder builder = new StringBuilder();
    builder.append("(\\w)");

    for (int i = 0; i < length - 1; i++) {
      builder.append("\\1");
    }

    return builder.toString();
  }

  /**
   * 숫자, 영어, 특수문자 조합 확인
   *
   * @return
   */
  private String digitAndWordAndSpecial() {
    return "([a-zA-Z0-9].*[!,@,#,$,%,^,&,*,?,_,~])|([!,@,#,$,%,^,&,*,?,_,~].*[a-zA-Z0-9])";
  }

  /**
   * 소문자, 대문자가 포함되어 있는지 확인
   *
   * @return
   */
  private String upperAndLower() {
    return "(?=.*[a-z])(?=.*[A-Z])";
  }

  /**
   * 한글 있는지 확인 패턴
   */
  private String hangeulPattern() {
    return "[ㄱ-ㅎ|ㅏ-ㅣ|가-힣]";
  }


  /**
   * 0 - 9 숫자
   *
   * @param length
   * @return
   */
  private String getDigit(int length) {
    final int repeat = 10;
    int repeatRepair = length - 2;

    if (repeatRepair < 0) {
      repeatRepair = 0;
    }

    StringBuilder builder = new StringBuilder();

    for (int digit = 0; digit < repeat - repeatRepair; digit++) {
      if (digit > 0 && digit < repeat - repeatRepair) {
        builder.append("|");
      }

      builder.append("(");
      for (int i = digit; i < length + digit; i++) {
        if (i > repeat - 1) {
          builder.append(0);
        } else {
          builder.append(i);
        }
      }

      builder.append(")");
    }

    return builder.toString();
  }

  /**
   * 0 - 9 역방향 숫자
   *
   * @param length
   * @return
   */
  private String getDigitReverse(int length) {
    final int repeat = 10;
    int repeatRepair = length - 2;

    if (repeatRepair < 0) {
      repeatRepair = 0;
    }

    StringBuilder builder = new StringBuilder();

    for (int digit = repeat; digit > repeatRepair; digit--) {
      if (digit < repeat && digit > 0) {
        builder.append("|");
      }

      builder.append("(");
      for (int i = digit; i > digit - length; i--) {
        if (i > repeat - 1) {
          builder.append(0);
        } else {
          builder.append(i);
        }
      }

      builder.append(")");
    }

    return builder.toString();
  }

  /**
   * a - z 소문자 알파벳
   *
   * @param length
   * @return
   */
  private String getAlphabet(int length) {
    final char repeat = 'z' + 1;
    int repeatRepair = length - 2;

    if (repeatRepair < 0) {
      repeatRepair = 0;
    }

    StringBuilder builder = new StringBuilder();

    for (char alphabet = 'a'; alphabet < repeat - repeatRepair; alphabet++) {
      if (alphabet > 'a' && alphabet < repeat - repeatRepair) {
        builder.append("|");
      }

      builder.append("(");
      for (char i = alphabet; i < length + alphabet; i++) {
        if (i > repeat - 1) {
          builder.append('a');
        } else {
          builder.append(i);
        }
      }

      builder.append(")");
    }

    return builder.toString();
  }

  /**
   * a - z 소문자 역방향 알파벳
   *
   * @param length
   * @return
   */
  private String getAlphabetReverse(int length) {
    final char repeat = 'z' + 1;
    int repeatRepair = length - 2;

    if (repeatRepair < 0) {
      repeatRepair = 0;
    }

    StringBuilder builder = new StringBuilder();

    for (char alphabet = repeat; alphabet > 'a' + repeatRepair; alphabet--) {
      if (alphabet < repeat && alphabet > 'a') {
        builder.append("|");
      }

      builder.append("(");
      for (char i = alphabet; i > alphabet - length; i--) {
        if (i > repeat - 1) {
          builder.append('a');
        } else {
          builder.append(i);
        }
      }

      builder.append(")");
    }

    return builder.toString();
  }

}
