package com.example.base.domain.member.service.valid.impl;

import com.example.base.common.exception.InvalidIdentityException;
import com.example.base.domain.member.service.valid.IdentityValidateService;
import org.springframework.stereotype.Service;

@Service
class IdentityValidateServiceImpl implements IdentityValidateService {

  @Override
  public void validate(String id) throws InvalidIdentityException {
    IdentityValidate identityValidate = new IdentityValidate(id)
            .minLength(6)
            .onlyDigit()
            .combineSpecial()
            .combineHangeul();

    switch (identityValidate.validate()) {
      case minWordLength, special, digit, hangeul -> {
        throw new InvalidIdentityException();
      }
    }
  }
}
