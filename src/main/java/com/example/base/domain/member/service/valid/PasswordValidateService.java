package com.example.base.domain.member.service.valid;

import com.example.base.common.exception.InvalidPasswordException;
import com.example.base.common.exception.NotSamePasswordException;

public interface PasswordValidateService {

  /**
   * 패스워드 밸리데이션 확인
   *
   * @param password
   * @param passwordConfirm
   * @throws InvalidPasswordException
   * @throws NotSamePasswordException
   */
  void validate(String password, String passwordConfirm) throws InvalidPasswordException, NotSamePasswordException;
}
