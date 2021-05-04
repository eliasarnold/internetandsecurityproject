package utils;


public class NetworkMaskChooser {
  public NetworkMaskChooser() {}
  
  public int getInt(char ch) { 
	int ret = 0xFFFFFF00;
    switch (ch) {
    case 'a': 
      ret = 0xFF000000;
    case 'b': 
      ret = 0xFFFF0000;
    case 'c': 
      ret = 0xFFFFFF00;
    }
    return ret;
  }
}
