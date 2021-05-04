package senders;


import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.Socket;

import visual.MessageWriter;

public class TCPconnector implements Runnable
{
  String IPaddr;
  int PortNr;
  MessageWriter mw;
  int fromPort;
  
  public TCPconnector(String ip, int port, MessageWriter m, int from) {
    IPaddr = ip;
    PortNr = port;
    mw = m;
    fromPort = from;
  }
  
  public void run(){
    try {
      mw.addMsg("Test: Baue TCP Verbindung mit " + IPaddr + ":" + Integer.toString(PortNr) + " auf!");
      //Socket s = new Socket(IPaddr, PortNr);
      Socket s = new Socket();
      s.bind(new InetSocketAddress(InetAddress.getLocalHost().getHostAddress(), fromPort));
      s.connect(new InetSocketAddress(this.IPaddr, this.PortNr));
      s.close();
    } catch (java.io.IOException e) {
      mw.addMsg("Fehler: TCP Aufbau fehlgeschlagen!");
    }
  }
}
