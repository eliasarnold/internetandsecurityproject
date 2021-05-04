package utils;

import java.util.Arrays;

import org.jnetpcap.Pcap;
import org.jnetpcap.PcapBpfProgram;
import org.jnetpcap.PcapIf;
import org.jnetpcap.packet.JHeader;
import org.jnetpcap.packet.PcapPacket;
import org.jnetpcap.packet.PcapPacketHandler;
import org.jnetpcap.protocol.network.Ip4;
import org.jnetpcap.protocol.tcpip.Tcp;

import visual.MessageWriter;

public class PackageHandler {
	private Tcp tcp_packet_tcp_header = null;
	private Ip4 tcp_packet_ip_header = null;
	private Ip4 icmp_packet_ip_header = null;
	private MessageWriter mw = null;
	
	public PackageHandler(MessageWriter mw){
		this.mw = mw;
	}
	
	public void addTcpHeader(Tcp tcp_header, Ip4 ip_header){
		this.tcp_packet_tcp_header = tcp_header;
		this.tcp_packet_ip_header = ip_header;
	}
	
	public void addIpHeader(Ip4 ip_header){
		this.icmp_packet_ip_header = ip_header;
	}
	
	public void getResult(){
		mw.addMsg("############### ARRAYS FÜR DIE ANALYSE ###############");
		int[] int_array = new int[4];
		boolean[] option_array = new boolean[3];
		
		int_array[0] = icmp_packet_ip_header.ttl();
		int_array[1] = tcp_packet_tcp_header.window();
		for (JHeader subheader : tcp_packet_tcp_header.getSubHeaders()){
			if(subheader instanceof Tcp.MSS){
				Tcp.MSS mss = (Tcp.MSS)subheader;
				int_array[2] = mss.mss();
			}
			if(subheader instanceof Tcp.WindowScale){
				Tcp.WindowScale winsc = (Tcp.WindowScale)subheader;
				int_array[3] = winsc.scale();
			}
		}
		mw.addMsg(Arrays.toString(int_array));
		option_array[0] = icmp_packet_ip_header.isFragmented();
		for(JHeader subheader : tcp_packet_tcp_header.getSubHeaders()){
			if(subheader instanceof Tcp.SACK_PERMITTED)
				option_array[1] = true;
			if(subheader instanceof Tcp.NoOp)
				option_array[2] = true;
		}
		mw.addMsg(Arrays.toString(option_array));
	}
}
