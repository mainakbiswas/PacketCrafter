package com.iitd.packetx;

public class UdpHeader {
	public int sport;
	public int dport;
	public int len;
	public int chkSum;
	
	public int calc_len = 1;
	public int calc_chksum = 1;
	
	public void setChkSum(int chk){
		calc_chksum = 0;
		chkSum = chk;
	}
	
	public void setLen(int len){
		calc_len = 0;
		this.len = len;
	}
}
