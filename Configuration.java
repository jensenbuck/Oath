package com.tarandrus.authenticator;


import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.Arrays;
import java.util.List;
import java.util.stream.Collectors;
import java.util.stream.IntStream;

import java.util.concurrent.TimeUnit;

public class Configuration {
  
  private static final int DEFAULT_AUTH_CODE_SIZE = 6;
  private static final int DEFAULT_PAST_INTERVAL_COUNT = 0;
  private static final long TIME_STEP_SIZE = TimeUnit.SECONDS.toMillis(30);
  
  private final int validPastIntervalCount;
  private final int authCodeSize;
  private final int authCodeModulus;

  
  public Configuration() {
    this(DEFAULT_AUTH_CODE_SIZE, DEFAULT_PAST_INTERVAL_COUNT);
  }
  
  public Configuration(int authCodeSize, int validPastIntervalCount) {
    this.authCodeSize = authCodeSize;
    this.validPastIntervalCount = validPastIntervalCount;
    authCodeModulus = (int) Math.pow(10, authCodeSize);
  }
  
  public int getValidPastIntervalCount() {
    return validPastIntervalCount;
  }
  
  public int getAuthCodeSize() {
    return authCodeSize;
  }
  
  public int getAuthCodeModulus() {
    return authCodeModulus;
  }
  
  public long getTimeStepSize() {
    return TIME_STEP_SIZE;
  }
  
}
 
  public boolean isAuthorized(String encodedSecretKey, int authCode, long time) 
      throws InvalidKeyException, NoSuchAlgorithmException { 
    
    if (encodedSecretKey == null) {
      throw new IllegalArgumentException("Secret cannot be null.");
    }
 
    if (authCode <= 0 || authCode >= configuration.getAuthCodeModulus()) {
      return false;
    }
    
    byte[] decodedSecretKey = new Base32().decode(encodedSecretKey);
    final long timeWindow = getWindowFromTime(time);
    
    for (int i = 0; i < configuration.getValidPastIntervalCount(); i++) {
      long hash = createAuthCode(decodedSecretKey, timeWindow - i);

      if (hash == authCode) {
        return true;
      }
    }

    return false; 
  }
 
  private long getWindowFromTime(long time) {
    return time/configuration.getTimeStepSize();
  }
     
  private List<Integer> getRandomSecureCodes() {
    return IntStream.range(0, 6)
      .boxed()
      .map(i -> createRandomSecureCode())
      .collect(Collectors.toList());
  }
    
  private int createRandomSecureCode() {
    while (true) {
      byte[] buffer = getRandomBytes(4);

      int secureCode = 0; 
      for (int i = 0; i < 4; ++i) {
        secureCode = (secureCode << 8) + (buffer[i] & 0xff);
      }

      secureCode = (secureCode & 0x7FFFFFFF) % SECURE_CODE_MODULUS;
 
      if (secureCode != -1 && secureCode >= SECURE_CODE_MODULUS/10) {
        return secureCode;
      }
    }
  }
  
  private byte[] getRandomBytes(int length) {
    byte[] buffer = new byte[length];
    secureRandom.nextBytes(buffer);
    
    byte[] randomBytes = Arrays.copyOf(buffer, 10);
    
    // forcing to base32 byte range
    for (int i=0; i<randomBytes.length; i++) {
      if (randomBytes[i] < 0) {
        randomBytes[i] += 128;
      }
    }
    
    return randomBytes;
  }
  
}
