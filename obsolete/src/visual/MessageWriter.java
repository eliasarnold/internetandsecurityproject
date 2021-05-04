package visual;


public class MessageWriter {
  StringBuffer sb;
  
  public MessageWriter() {
    sb = new StringBuffer("");
  }
  
  public void addMsg(String msg) {
    sb.append("\n" + msg);
  }
  
  String getMsg() {
    return sb.toString();
  }
}
