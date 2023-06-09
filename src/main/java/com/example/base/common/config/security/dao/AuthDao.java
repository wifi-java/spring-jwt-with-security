package com.example.base.common.config.security.dao;

import com.example.base.domain.member.model.member.AuthTokenEntity;
import com.example.base.domain.member.model.member.Member;

import java.util.Optional;

public interface AuthDao {

  Optional<Member> selectAccount(Member member);

  Optional<AuthTokenEntity> selectAuthToken(AuthTokenEntity authToken);

  void insertAuthToken(AuthTokenEntity authToken);
}
