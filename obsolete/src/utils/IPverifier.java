package utils;


import java.util.regex.Pattern;

public class IPverifier
{
  String Input;
  String IPAddress;
  int PortNr;
  boolean good = false;
  
  public IPverifier(String inp) {
    Input = inp;
    extractInput();
  }
  
  void extractInput() {
    Pattern p = Pattern.compile("[0-9]+[.][0-9]+[.][0-9]+[.][0-9]+[:][0-9]+");
    java.util.regex.Matcher m = p.matcher(Input);
    if (m.matches()) {
      String[] parts = Input.split("[:]");
      IPAddress = parts[0];
      PortNr = Integer.parseInt(parts[1]);
      if ((PortNr >= 1024) && (PortNr <= 65535)) {
        good = true;
      }
    }
  }
  
  public boolean isGood() {
    return good;
  }
  
  public String getIP() {
    return IPAddress;
  }
  
  public int getPort() {
    return PortNr;
  }
}
