package com.example.base.domain.member.controller;

import com.example.base.common.util.AuthUtils;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.GetMapping;

import java.util.Objects;

@Controller
@Slf4j
public class MemberController {

  @GetMapping("/login")
  public String login() {
    if (AuthUtils.getMemberAuth().isPresent()) {
      return "redirect:/";
    }

    return "/login";
  }

  @GetMapping("/sign-up")
  public String signup() {
    if (AuthUtils.getMemberAuth().isPresent()) {
      return "redirect:/";
    }

    return "/signup";
  }
}
