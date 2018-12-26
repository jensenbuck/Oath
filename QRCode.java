package com.tarandrus.authenticator;

public class QRCode {

  private static final String ROOT = "https://chart.googleapis.com/chart?cht=qr";
  private static final int DEFAULT_HEIGHT = 200;
  private static final int DEFAULT_WIDTH = 200;
  
  
  private final int height;
  private final int width;
  private final String urlEncodedData;
  
  public QRCode(String urlEncodedData) {
    this(urlEncodedData, DEFAULT_WIDTH, DEFAULT_HEIGHT);
  }
  
  public QRCode(String urlEncodedData, int width, int height) {
    this.urlEncodedData = urlEncodedData;
    this.width = width; 
    this.height = height;
  }
  
  public String getUrl() {
    return ROOT + "&chs=" + width + "x" + height + "&chl=" + urlEncodedData;
  }
}
