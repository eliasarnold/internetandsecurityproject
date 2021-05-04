import java.net.InetAddress;
import java.net.UnknownHostException;
import java.util.ArrayList;
import java.util.List;
import java.util.Scanner;
import org.jnetpcap.Pcap;
import org.jnetpcap.PcapBpfProgram;
import org.jnetpcap.PcapIf;
import org.jnetpcap.packet.PcapPacket;
import org.jnetpcap.packet.PcapPacketHandler;
import org.jnetpcap.protocol.network.Ip4;
import org.jnetpcap.protocol.tcpip.Tcp;

import senders.SendPing;
import senders.TCPconnector;
import utils.IPverifier;
import utils.NetworkMaskChooser;
import utils.PackageHandler;
import visual.MessageWriter;
import visual.Waiter;

public class ClassicPcapExample
{
  public ClassicPcapExample() {}
  
  public static void main(String[] args) throws UnknownHostException
  {
    List<PcapIf> alldevs = new ArrayList<PcapIf>();
    StringBuilder errbuf = new StringBuilder();
    

    int r = Pcap.findAllDevs(alldevs, errbuf);
    if ((r == -1) || (alldevs.isEmpty())) {
      System.err.printf("Can't read list of devices, error is %s", new Object[] { errbuf.toString() });
      return;
    }
    
    System.out.println("Gefundene Netzwerkkarten:");
    
    int i = 0;
    for (PcapIf device : alldevs) {
      String description = 
        device.getDescription() != null ? device.getDescription() : "Keine Beschreibung verfügbar";
      System.out.printf("#%d: %s [%s]\n", new Object[] { Integer.valueOf(i++), device.getName(), description });
    }
    
    int index;
    Scanner sc = new Scanner(System.in);
    while(true){
      System.out.print("\nWählen Sie eine Netzwerkkarte aus der obenstehenden Liste aus, indem Sie deren Index eingeben: ");
      if (sc.hasNextInt()) {
        int input = sc.nextInt();
        if ((input < 0) || (input > i-1)) {
          System.out.println("Der eingegebene Wert liegt nicht im erlaubten Intervall!");
        } else {
          index = input;
          break;
        }
      } else {
        System.out.println("Die Eingabe muss eine Ganzzahl sein, die einem Index aus der obigen Liste entspricht!");
        sc.next();
      }
    }
    
    PcapIf device = (PcapIf)alldevs.get(index);
    System.out.printf("\nWähle '%s' für die Aufzeichung:\n",(device.getDescription() != null) ? device.getDescription(): device.getName());
    

    int maske = 0xFFFFFF00;
    while(true){
      System.out.print("\nGeben Sie den Typspezifischen Bezeichner des Netzwerkes(A, B oder C) ein, in dem Sie sich befinden: ");
      if (sc.hasNext()) {
        char input = sc.next().toLowerCase().charAt(0);
        if ((input == 'a') || (input == 'b') || (input == 'c')) {
          NetworkMaskChooser nmch = new NetworkMaskChooser();
          maske = nmch.getInt(input);
          break;
        }
        System.out.println("Ungültige Eingabe");
        //sc.next();
      }
    }
    



    int PortNr;
    String IPAdd;
    while(true){
      System.out.print("\nGeben Sie eine IPv4 Adresse, gefolgt von der gewünschten Portnummer ein. E.g. <192.168.1.125:6665>: ");
      String str = sc.next();
      IPverifier veri = new IPverifier(str);
      if (veri.isGood()) {
        IPAdd = veri.getIP();
        PortNr = veri.getPort();
        break;
      }
      System.out.println("Ungültige Eingabe!"); 
    }
    

    int fromPort;
    while(true){
    	System.out.print("\nGeben Sie eine Portnummer ein, von der aus eine TCP-Verbindung zum gewählten Ziel ("+IPAdd+":"+Integer.toString(PortNr)+") aufgebaut werden soll: ");
    	if(sc.hasNextInt()){
    		fromPort = sc.nextInt();
    		if(fromPort >= 0 && fromPort <= 65535)
    			break;
    		else
    			System.out.println("Der eingegebene Wert liegt nicht im erlaubten Intervall!");
    	} else {
    		System.out.println("Ungültige Eingabe!");
    		sc.next();
    	}
    }
    
    sc.close();
    System.out.println("");
    

    MessageWriter mw = new MessageWriter();
    
    Waiter waiter = new Waiter(mw);
    Thread waiter_thread = new Thread(waiter);
    waiter_thread.start();
    

    SendPing send_ping = new SendPing(IPAdd, PortNr, mw);
    Thread ping_thread = new Thread(send_ping);
    ping_thread.start();
    
    TCPconnector send_tcp = new TCPconnector(IPAdd, PortNr, mw, fromPort);
    Thread tcp_thread = new Thread(send_tcp);
    tcp_thread.start();
    


    int snaplen = 64 * 1024;
    int flags = Pcap.MODE_PROMISCUOUS;
    int timeout = 7 * 1000;
    Pcap pcap = Pcap.openLive(device.getName(), snaplen, flags, timeout, errbuf);
    
    if (pcap == null) {
      System.err.printf("Error while opening device for capture: " + 
        errbuf.toString(), new Object[0]);
      return;
    }
    


    PcapBpfProgram filter_1 = new PcapBpfProgram();
    String expression = "src host " + IPAdd + " and (tcp or icmp[icmptype] == icmp-echoreply)";
    int optimize = 0;
    int netmask = maske;
    if (pcap.compile(filter_1, expression, optimize, netmask) != 0) {
      System.err.println(pcap.getErr());
      return;
    }
    if (pcap.setFilter(filter_1) != 0) {
      System.err.println(pcap.getErr());
      return;
    }
    PackageHandler ph = new PackageHandler(mw);
    PcapPacketHandler<String> jpacketHandler_for_ping = new PcapPacketHandler<String>() {
    	boolean tcp_packet_captured = false;
    	boolean icmp_packet_captured = false;
    	/*
		 * Die "loop"-Funktion von Pcap führt die "nextPacket"-Funktion des PcapPacketHandlers sooft aus, wie im ersten Argument von 
		 * "loop" angegeben wurde!
    	 */
    	public void nextPacket(PcapPacket packet, String user) {
    		Ip4 ip = new Ip4();
    		Tcp tcp = new Tcp();
    		if (packet.hasHeader(ip)) {
    			if (packet.hasHeader(tcp) && tcp_packet_captured == false) {
    				tcp_packet_captured = true;
    				mw.addMsg("############### TCP-PAKET ###############");
    				mw.addMsg(ip.toString());
    				mw.addMsg(tcp.toString());
    				ph.addTcpHeader(tcp,ip);
    			} else {
    				if(icmp_packet_captured == false){
    					icmp_packet_captured = true;
    					mw.addMsg("############### ICMP-PAKET ###############");
    					mw.addMsg(ip.toString());
    					ph.addIpHeader(ip);
    				}
    			}
    		}
    	}
    };
    pcap.loop(3, jpacketHandler_for_ping, "Optionaler String");
    ph.getResult();
    pcap.close();
  }
}
