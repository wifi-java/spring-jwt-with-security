package com.example.base.domain.member.service.valid.impl;

import com.example.base.common.exception.InvalidPasswordException;
import com.example.base.common.exception.NotSamePasswordException;
import com.example.base.domain.member.service.valid.PasswordValidateService;
import org.apache.commons.lang3.StringUtils;
import org.springframework.stereotype.Service;

@Service
class PasswordValidateServiceImpl implements PasswordValidateService {

  @Override
  public void validate(String password, String passwordConfirm) throws InvalidPasswordException, NotSamePasswordException {
    if (StringUtils.isEmpty(password) || StringUtils.isEmpty(passwordConfirm) || !password.equals(passwordConfirm)) {
      throw new NotSamePasswordException();
    }

    PasswordValidate passwordValidate = new PasswordValidate(password)
            .minLength(8)
            .maxLength(20)
            .combineHangeul()
            .combineDigitAndWordAndSpecial();

    switch (passwordValidate.validate()) {
      case minWordLength, maxWordLength, upperLower, notDigitAndWordAndSpecial, hangeul -> {
        throw new InvalidPasswordException();
      }
    }
  }
}
