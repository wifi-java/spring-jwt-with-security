package com.example.base.domain.member.dao;

import com.example.base.domain.member.model.member.Member;

import java.util.Optional;

public interface MemberDao {
  /**
   * 회원 정보 조회
   *
   * @param member
   */
  Optional<Member> selectMember(Member member);

  /**
   * 회원 가입
   *
   * @param member
   */
  void insertMember(Member member);
}
