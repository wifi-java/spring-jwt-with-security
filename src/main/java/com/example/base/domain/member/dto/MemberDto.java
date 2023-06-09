package com.example.base.domain.member.dto;

import com.example.base.domain.member.model.member.Member;
import io.swagger.v3.oas.annotations.media.Schema;
import lombok.Data;

public class MemberDto {

  @Data
  public static class InfoRes {
    @Schema(description = "아이디", required = true)
    private String id;

    @Schema(description = "이름", required = true)
    private String name;

    @Schema(description = "가입 채널", required = true)
    private String channel;
  }

  public static Member toEntity(MemberDto.InfoRes req) {
    Member member = new Member();
    member.setId(req.id);
    member.setName(req.name);
    member.setChannel(req.channel);

    return member;
  }

  public static InfoRes toDto(Member member) {
    InfoRes res = new InfoRes();
    res.setId(member.getId());
    res.setName(member.getName());
    res.setChannel(member.getChannel());

    return res;
  }

}
