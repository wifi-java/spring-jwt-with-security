package com.example.base.domain.member.dto;

import com.example.base.domain.member.model.member.Member;
import io.swagger.v3.oas.annotations.media.Schema;
import lombok.Data;

public class SignUpDto {

  @Data
  public static class SignReq {
    @Schema(description = "이름", required = true)
    private String name;

    @Schema(description = "아이디", required = true)
    private String id;

    @Schema(description = "비밀번호", required = true)
    private String pw;

    @Schema(description = "비밀번호 확인", required = true)
    private String pwConfirm;

    @Schema(description = "가입 채널", required = true)
    private String channel;
  }

  public static Member toEntity(SignReq req) {
    Member member = new Member();
    member.setName(req.name);
    member.setId(req.id);
    member.setPw(req.pw);
    member.setPwConfirm(req.pwConfirm);
    member.setChannel(req.channel);

    return member;
  }
}
