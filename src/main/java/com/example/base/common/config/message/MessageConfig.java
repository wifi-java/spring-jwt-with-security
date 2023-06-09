package com.example.base.common.config.message;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.support.MessageSourceAccessor;
import org.springframework.context.support.ReloadableResourceBundleMessageSource;

@Configuration
public class MessageConfig {
  @Value("${spring.messages.basename}")
  private String messagesBasename;

  @Value("${spring.messages.encoding}")
  private String messagesEncoding;

  @Value("${spring.messages.cache-duration}")
  private int messagesCacheSeconds;

  @Bean
  public ReloadableResourceBundleMessageSource messageSource() {
    ReloadableResourceBundleMessageSource messageSource = new ReloadableResourceBundleMessageSource();
    messageSource.setBasenames(messagesBasename.split(","));
    messageSource.setDefaultEncoding(messagesEncoding);
    messageSource.setCacheSeconds(messagesCacheSeconds);
    return messageSource;
  }

  @Bean
  public MessageSourceAccessor messageSourceAccessor() {
    ReloadableResourceBundleMessageSource messageSource = messageSource();
    return new MessageSourceAccessor(messageSource);
  }
}
