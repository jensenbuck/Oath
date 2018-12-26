package com.tarandrus.authenticator;

import java.util.concurrent.TimeUnit;

public class Configuration {
  
  private static final int DEFAULT_AUTH_CODE_SIZE = 6;
  private static final int DEFAULT_INTERVAL_WINDOW = 3;
  private static final long TIME_STEP_SIZE = TimeUnit.SECONDS.toMillis(30);
  
  private final int intervalWindow;
  private final int authCodeSize;
  private final int authCodeModulus;
  
  
  public Configuration() {
    this(DEFAULT_AUTH_CODE_SIZE, DEFAULT_INTERVAL_WINDOW);
  }
  
  public Configuration(int authCodeSize, int intervalWindow) {
    this.authCodeSize = authCodeSize;
    this.intervalWindow = intervalWindow;
    authCodeModulus = (int) Math.pow(10, authCodeSize);
  }
  
  public int getIntervalWindow() {
    return intervalWindow;
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
