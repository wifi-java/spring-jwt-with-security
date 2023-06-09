package com.example.base.domain.member.service.signup;

import com.example.base.common.exception.ExistIdException;
import com.example.base.common.exception.SignUpException;
import com.example.base.domain.member.model.member.Member;

/**
 * 회원 가입을 관장하는 클래스
 */
public interface SignUpService {
  /**
   * 일반 회원가입
   *
   * @param member
   * @throws SignUpException  회원 가입중 오류
   */
  void signUpForNormal(Member member) throws SignUpException;


  /**
   * SNS 회원가입
   *
   * @param member
   * @throws SignUpException  회원 가입중 오류
   */
  void signUpForSocial(Member member) throws SignUpException;

  /**
   * 사용중인 아이디인지 확인
   *
   * @param member
   * @throws ExistIdException
   */
  void checkExistIdentity(Member member) throws ExistIdException;
}
