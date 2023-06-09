package com.example.base.domain.member.dto;

import com.example.base.domain.member.model.member.Member;
import io.swagger.v3.oas.annotations.media.Schema;
import lombok.Data;

public class AuthDto {

  @Data
  public static class AuthReq {
    @Schema(description = "아이디", required = true)
    private String id;

    @Schema(description = "비밀번호", required = true)
    private String pw;

    @Schema(description = "가입 채널", required = true)
    private String channel;
  }

  @Data
   public static class AuthRes {
     @Schema(description = "액세스 토큰", required = true)
     private String accessToken;

   }

  public static Member toEntity(AuthReq req) {
    Member member = new Member();
    member.setId(req.id);
    member.setPw(req.pw);
    member.setChannel(req.channel);

    return member;
  }
}
