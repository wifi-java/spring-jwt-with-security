package com.example.base.common.response;

public enum Status {
  SUCCESS(0, "성공"),
  FAIL(-1, "실패"),
  LOGIN_FAIL(90, "아이디 또는 비밀번호 잘못되었습니다."),
  AUTHENTICATION_FAIL(91, "계정 인증에 실패했습니다."),
  ACCOUNT_DORMANCY(92, "휴면 계정입니다."),
  ACCOUNT_LOCK(93, "잠김 계정입니다."),
  ACCESS_DENIED(94, "접근 권한이 없습니다."),
  UNAUTHORIZED(95, "인증 정보가 잘못되었거나 인가되지 않은 사용자입니다."),
  EXIST_ID(100, "이미 사용중인 아이디입니다."),
  NOT_SAME_PASSWORD(101, "비밀번호가 일치하지 않습니다."),
  INVALID_ID(102, "아이디는 6자 이상의 영문/영문+숫자로 입력해주세요."),
  INVALID_PW_ERROR(103, "비밀번호는 영문(대소문자 구분)+숫자+특수문자 포함 8~20자리로 입력해주세요."),
  SIGN_UP_FAIL(104, "회원가입중 오류가 발생했습니다."),
  INVALID_TYPE_VALUE(400, "INVALID_TYPE_VALUE");

  private final int code;
  private String message;

  Status(final int code, final String message) {
    this.message = message;
    this.code = code;
  }

  public void setMessage(String message) {
    this.message = message;
  }

  public String getMessage() {
    return this.message;
  }

  public int getCode() {
    return code;
  }
}
