package com.example.base.domain.member.controller.rest;

import com.example.base.domain.member.service.MemberService;
import org.json.JSONObject;
import org.junit.jupiter.api.*;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.http.MediaType;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.setup.MockMvcBuilders;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.web.context.WebApplicationContext;

import static org.springframework.security.test.web.servlet.setup.SecurityMockMvcConfigurers.springSecurity;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultHandlers.print;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

@SpringBootTest
@AutoConfigureMockMvc
@TestMethodOrder(MethodOrderer.OrderAnnotation.class)
@Transactional
class MemberRestControllerTest {

  @Autowired
  private WebApplicationContext applicationContext;

  @Autowired
  private MemberService memberService;

  @Autowired
  private MockMvc mockMvc;

  @BeforeEach
  public void mockMvcSetUp() {
    this.mockMvc = MockMvcBuilders.webAppContextSetup(applicationContext).apply(springSecurity()).build();
  }

  @Order(1)
  @Test
  @DisplayName("회원가입 테스트")
  public void signUpTest() throws Exception {
    JSONObject jsonObject = new JSONObject();
    jsonObject.put("name", "테스터");
    jsonObject.put("id", "test12341");
    jsonObject.put("pw", "a123145234!");
    jsonObject.put("pwConfirm", "a123145234!");

    mockMvc.perform(post("/api/member/v1/sign-up")
                    .content(jsonObject.toString())
                    .contentType(MediaType.APPLICATION_JSON)
                    .accept(MediaType.APPLICATION_JSON))
            .andExpect(status().isOk())
            .andDo(print());
  }

}