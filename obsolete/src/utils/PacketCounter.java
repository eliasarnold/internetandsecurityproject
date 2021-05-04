package utils;


public class PacketCounter { public PacketCounter() {}
  static int number = 0;
  
  public static void increase() {
    number += 1;
  }
  
  public static int getNum() {
    return number;
  }
}
