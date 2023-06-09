package com.example.base.domain.member.model.member;

import lombok.Data;

/**
 * @TABLE: TB_MEMBER
 * <br> 테이블 컬럼과 일치화시켜 클래스만 보더라도 테이블에 어떤 컬럼이 존재하는지 확인할 수 있다.
 */
@Data
class MemberEntity {
    /**
     * 시퀀스 넘버
     */
    protected int idx;

    /**
     * 아이디
     */
    protected String id;

    /**
     * 이름
     */
    protected String name;

    /**
     * 비밀번호
     */
    protected String pw;

    /**
     * 가입 채널
     */
    protected String channel;
}
