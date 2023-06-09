package com.example.base.domain.member.service.valid;

import com.example.base.common.exception.InvalidIdentityException;

public interface IdentityValidateService {

  /**
   * 아이디 밸리데이션 확인
   *
   * @param id
   * @throws InvalidIdentityException
   */
  void validate(String id) throws InvalidIdentityException;
}
