package senders;

import visual.MessageWriter;

public class SendPing implements Runnable {
  String IPAddr;
  int PortNr;
  MessageWriter mw;
  
  public SendPing(String ip, int port, MessageWriter m) {
    IPAddr = ip;
    PortNr = port;
    mw = m;
  }
  
  public void run()
  {
    try {
      @SuppressWarnings("unused")
      Process p = Runtime.getRuntime().exec("ping " + IPAddr);
      
      mw.addMsg("Test: Sende ICMP-Ping Paket an " + IPAddr + "!");
    } catch (Exception e) {
      mw.addMsg("Fehler: Empfangen der Ping-Response fehlgeschlagen!");
    }
  }
}
