package com.example.base.domain.member.service.signup.impl;

import com.example.base.common.exception.ExistIdException;
import com.example.base.common.exception.SignUpException;
import com.example.base.domain.member.dao.MemberDao;
import com.example.base.domain.member.model.member.Member;
import com.example.base.domain.member.service.signup.SignUpService;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Component;

@RequiredArgsConstructor
@Component
@Slf4j
class SignUpServiceImpl implements SignUpService {
  private final MemberDao memberDao;
  private final PasswordEncoder passwordEncoder;

  @Override
  public void signUpForNormal(Member member) throws SignUpException {
    try {
      member.setPw(passwordEncoder.encode(member.getPw()));
      memberDao.insertMember(member);
    } catch (Exception e) {
      throw new SignUpException();
    }
  }

  @Override
  public void signUpForSocial(Member member) throws SignUpException {
    try {
      // SNS 계정은 비밀번호가 없기 때문에 더미로 비밀번호를 만들어준다.
      String dummyPw = "Temp!23";
      member.setPw(passwordEncoder.encode(dummyPw));
      memberDao.insertMember(member);
    } catch (Exception e) {
      throw new SignUpException();
    }
  }

  @Override
  public void checkExistIdentity(Member member) throws ExistIdException {
    memberDao.selectMember(member).ifPresent(data -> {
      throw new ExistIdException();
    });
  }
}
