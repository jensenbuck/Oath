package com.tarandrus.authenticator;

import java.util.Collections;
import java.util.List;

public class Credentials {

  private final Configuration configuration;
  private final String secretKey;
  private final int verificationCode;
  private final List<Integer> randomSecureCodes;
  
  public Credentials(Configuration configuration, String secretKey, int verificationCode, List<Integer> possibles) {
    this.configuration = configuration;
    this.secretKey = secretKey;
    this.verificationCode = verificationCode;
    this.randomSecureCodes = Collections.unmodifiableList(possibles);
  }
  
  public Configuration getConfiguration() {
    return configuration;
  }
  
  public String getSecretKey() {
    return secretKey;
  }
  
  public int getVerificationCode() {
    return verificationCode;
  }
  
  public List<Integer> getRandomSecureCodes() {
    return randomSecureCodes;
  }
  
}