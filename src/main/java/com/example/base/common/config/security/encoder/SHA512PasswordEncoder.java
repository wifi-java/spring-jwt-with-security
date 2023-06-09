package com.example.base.common.config.security.encoder;

import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Component;

@Component
public class SHA512PasswordEncoder implements PasswordEncoder {

  @Value("${spring.salt}")
  private String salt;

  @Override
  public String encode(CharSequence rawPassword) {
    return hashWithSHA512(rawPassword.toString());
  }

  @Override
  public boolean matches(CharSequence rawPassword, String encodedPassword) {
    String hashedPassword = encode(rawPassword);
    return encodedPassword.equals(hashedPassword);
  }

  private String hashWithSHA512(String input) {
    StringBuilder result = new StringBuilder();
    try {
      MessageDigest md = MessageDigest.getInstance("SHA-512");
      md.update(salt.getBytes());

      byte[] digested = md.digest(input.getBytes());
      for (byte b : digested) {
        result.append(Integer.toHexString(0xFF & b));
      }
    } catch (NoSuchAlgorithmException e) {
      throw new RuntimeException("Bad algorithm");
    }
    return result.toString();
  }
}
