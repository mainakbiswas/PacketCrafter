package com.iitd.packetx;

public class Ipv4Header {
	public int hdrLen = 5; //default header length
	public int version = 4;    //ipv6 not supported yet, as we could not test it.
	public int tos = 0; //Combination of DSCP and ECN field, best set using hex digits.
	public int totLen = 0; 
	public int id = 655;  //arbitrary number
	public int fragOff = 0; //the flags E D M and offset, best set using hex digits.
	public int ttl = 255; //default ttl
	public int chkSum = 0;
	public String sourceIp = "";
	public String destIp = "";
	public int protocol;
	
	//used for automatic computation if not specified by user
	public int calc_chkSum = 1;
	public int calc_totLen = 1;
	
	public Ipv4Header(){
		//keep default values;
	}
	
	public Ipv4Header(int hl, int ver, int tos, int id, int fo, int ttl, String sip, String dip){
		hdrLen = hl;
		version = ver;
		this.tos = tos;
		this.id = id;
		fragOff = fo;
		this.ttl = ttl;
		sourceIp = sip;
		destIp = dip;
	}
	
	public void setChkSum(int chk){
		calc_chkSum = 0;
		chkSum = chk;
	}
	
	public void setTotLen(int len){
		calc_totLen = 0;
		totLen = len;
	}
	
	public void incrementId(){
		id = (id +1) % 65533 ;
	}
	
	public void setId(int id){
		if(id <=65533)
			this.id = id;
		else
			this.id = 65533;
	}
}

