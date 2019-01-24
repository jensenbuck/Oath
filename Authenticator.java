package com.tarandrus.authenticator;

import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.Arrays;
import java.util.List;
import java.util.stream.Collectors;
import java.util.stream.IntStream;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;

import com.tarandrus.base32.Base32;


public class Authenticator {

  private static final String HMAC_SHA1 = "HmacSHA1"; 
  private static final int SECURE_CODE_MODULUS = (int) Math.pow(10, 8);
  
  private final Configuration configuration;
  private final SecureRandom secureRandom;
  
  public Authenticator() {
    this(new Configuration());
  }
  
  public Authenticator(Configuration configuration) {
    this.configuration = configuration;
    secureRandom = new SecureRandom();
  }
   
  public int createAuthCode(String encodedSecretKey, long timeInMillis) throws InvalidKeyException, NoSuchAlgorithmException {
    return createAuthCode(
      new Base32().decode(encodedSecretKey),
      getWindowFromTime(timeInMillis)
    );
  }
  
  public int createAuthCode(byte[] decodedSecretKey, long timeMillis) 
      throws NoSuchAlgorithmException, InvalidKeyException {
    
    byte[] data = new byte[8];
    long value = timeMillis;
 
    for (int i = 8; i-- > 0; value >>>= 8) {
      data[i] = (byte) value;
    }
 
    Mac mac = Mac.getInstance(HMAC_SHA1); 
    mac.init(new SecretKeySpec(decodedSecretKey, HMAC_SHA1));
 
    byte[] hash = mac.doFinal(data); 
    int offset = hash[hash.length - 1] & 0xF;
    
    long truncatedHash = 0; 
    for (int i = 0; i < 4; ++i) {
      truncatedHash <<= 8;
      truncatedHash |= (hash[offset + i] & 0xFF);
    }

    truncatedHash &= 0x7FFFFFFF;
    truncatedHash %= configuration.getAuthCodeModulus();
 
    return (int) truncatedHash;
  }
 
  public Credentials createCredentials() throws InvalidKeyException, NoSuchAlgorithmException { 
    byte[] secretBytes = getRandomBytes(10); 
    
    // create credentials at time 0
    return new Credentials(
      configuration,
      new Base32().encode(secretBytes),           // encoded secret key
      createAuthCode(secretBytes, 0),             // authentication code @ 0 time 
      getRandomSecureCodes()
    );
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
