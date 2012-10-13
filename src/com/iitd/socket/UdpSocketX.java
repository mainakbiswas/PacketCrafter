package com.iitd.socket;

import com.iitd.packetx.Ipv4Header;
import com.iitd.packetx.Protocol;
import com.iitd.packetx.UdpHeader;

public class UdpSocketX {
	private Ipv4Header iphdr;
	private UdpHeader udphdr;
	
	public UdpSocketX(String srcIp, String destIp, int sport, int dport){
		iphdr = new Ipv4Header();
		iphdr.sourceIp = srcIp;
		iphdr.destIp = destIp;
		iphdr.protocol = Protocol.UDP;
		
		udphdr = new UdpHeader();
		udphdr.sport = sport;
		udphdr.dport = dport;
	}
	
	public void set_IpHeader_ihl(int ihl){
		iphdr.hdrLen = ihl;
	}
	
	public void set__IpHeader_tos(int tos){
		iphdr.tos = tos;
	}
	
	public void set__IpHeader_totalLength(int tot){
		iphdr.setTotLen(tot);
	}
	
	public void set__IpHeader_version(int ver){
		iphdr.version = ver;
	}
	
	public void set__IpHeader_id(int id){
		iphdr.setId(id);
	}
	
	public void set__IpHeader_fragoff(int fo){
		iphdr.fragOff = fo;
	}
	
	public void set__IpHeader_ttl(int ttl){
		iphdr.ttl = ttl;
	}
	
	public void set__IpHeader_chksum(int chk){
		iphdr.setChkSum(chk);
	}
	
	public void set_UdpHeader_chksum(int chk){
		udphdr.setChkSum(chk);
	}
	
	public void set_UdpHeader_len(int len){
		udphdr.setLen(len);
	}
	
	//send should reset totlen and chksum fields
	private native int sendUdpPacket(Ipv4Header iph, UdpHeader udph, String data);
	
	public int sendData(String data){
		int ret = sendUdpPacket(iphdr, udphdr, data);
		
		iphdr.calc_chkSum = 1;
		iphdr.calc_totLen = 1;
		udphdr.calc_chksum = 1;
		udphdr.calc_chksum = 1;
		return ret;
	}
}

