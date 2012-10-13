#include <jni.h>
#include "com_iitd_socket_UdpSocketX.h"

#include <android/log.h>

#include <string.h>
#include <arpa/inet.h>
#include<string.h> //memset
#include<sys/socket.h>	//for socket ofcourse
#include<stdlib.h> //for exit(0);
#include<errno.h> //For errno - the error number
#include<netinet/udp.h>	//Provides declarations for udp header
#include<netinet/ip.h>	//Provides declarations for ip header


/* 
 96 bit (12 bytes) pseudo header needed for udp header checksum calculation 
 */
struct pseudo_header
{
	u_int32_t source_address;
	u_int32_t dest_address;
	u_int8_t placeholder;
	u_int8_t protocol;
	u_int16_t udp_length;
};

/*
 Generic checksum calculation function
 */
unsigned short csum(unsigned short *ptr,int nbytes) 
{
	register long sum;
	unsigned short oddbyte;
	register short answer;
	
	sum=0;
	while(nbytes>1) {
		sum+=*ptr++;
		nbytes-=2;
	}
	if(nbytes==1) {
		oddbyte=0;
		*((u_char*)&oddbyte)=*(u_char*)ptr;
		sum+=oddbyte;
	}
	
	sum = (sum>>16)+(sum & 0xffff);
	sum = sum + (sum>>16);
	answer=(short)~sum;
	
	return(answer);
}


JNIEXPORT jint JNICALL Java_com_iitd_socket_UdpSocketX_sendUdpPacket
  (JNIEnv *env, jobject obj, jobject iphdr, jobject udphdr, jstring dataToSend)
{
	const char *datasend = (*env)->GetStringUTFChars(env, dataToSend, 0);
	int s = socket (PF_INET, SOCK_RAW, IPPROTO_UDP);
	
	if(s == -1)
	{
		__android_log_print(ANDROID_LOG_INFO, "MYPROG", "ajob errno = %d, %s", s, strerror(s));
		//socket creation failed, may be because of non-root privileges
		perror("Failed to create socket");
		return -1;
	}
	
	//Datagram to represent the packet
	char datagram[65536] , source_ip[32] , *data , *pseudogram;
	
	//zero out the packet buffer
	memset (datagram, 0, 65536);
	
	//IP header
	struct iphdr *iph = (struct iphdr *) datagram;
	
	//UDP header
	struct udphdr *udph = (struct udphdr *) (datagram + sizeof (struct ip));
	struct sockaddr_in sin;
	struct pseudo_header psh;
	
	//Data part
	data = datagram + sizeof(struct iphdr) + sizeof(struct udphdr);
	strcpy(data , datasend);
	
	jclass ipClass = (*env)->GetObjectClass(env, iphdr);
	jclass udpClass = (*env)->GetObjectClass(env, udphdr);
	jfieldID fid;
	 
	
	//get sip and dip
	char sip[32];
	char dip[32];
	fid = (*env)->GetFieldID(env, ipClass, "sourceIp", "Ljava/lang/String;");
	jstring str = (*env)->GetObjectField(env, iphdr, fid);
	const char *cStr = (*env)->GetStringUTFChars(env, str, NULL);
	strcpy(sip,cStr);
	(*env)->ReleaseStringUTFChars(env, str, cStr);
		
	fid = (*env)->GetFieldID(env, ipClass, "destIp", "Ljava/lang/String;");
	str = (*env)->GetObjectField(env, iphdr, fid);
	cStr = (*env)->GetStringUTFChars(env, str, NULL);
	strcpy(dip,cStr);
	(*env)->ReleaseStringUTFChars(env, str, cStr);
	
	//some address resolution
	strcpy(source_ip , sip);
	sin.sin_family = AF_INET;
	jint dport;
	fid = (*env)->GetFieldID(env, udpClass, "dport", "I");
	dport = (*env)->GetIntField(env, udphdr, fid);
	sin.sin_port = htons(dport);
	sin.sin_addr.s_addr = inet_addr (dip);

	//Fill in the IP Header
        
        jint tmp;
        fid = (*env)->GetFieldID(env, ipClass, "hdrLen", "I");
        tmp = (*env)->GetIntField(env, iphdr, fid);
	iph->ihl = tmp;
	
	fid = (*env)->GetFieldID(env, ipClass, "version", "I");
        tmp = (*env)->GetIntField(env, iphdr, fid);
	iph->version = tmp;
	
	fid = (*env)->GetFieldID(env, ipClass, "tos", "I");
        tmp = (*env)->GetIntField(env, iphdr, fid);
	iph->tos = tmp;       //ecn bits etc
	
	fid = (*env)->GetFieldID(env, ipClass, "calc_totLen", "I");
        tmp = (*env)->GetIntField(env, iphdr, fid);
        if(tmp == 1) {
		iph->tot_len = sizeof (struct iphdr) + sizeof (struct udphdr) + strlen(data);
	}
	else{
		fid = (*env)->GetFieldID(env, ipClass, "totLen", "I");
        	tmp = (*env)->GetIntField(env, iphdr, fid);
        	iph->tot_len = tmp;
	}
	
	fid = (*env)->GetFieldID(env, ipClass, "id", "I");
        tmp = (*env)->GetIntField(env, iphdr, fid);
	iph->id = htonl (tmp);	//Id of this packet
	
	fid = (*env)->GetFieldID(env, ipClass, "fragOff", "I");
        tmp = (*env)->GetIntField(env, iphdr, fid);
	iph->frag_off = tmp;  //flags cum offset
	
	fid = (*env)->GetFieldID(env, ipClass, "ttl", "I");
        tmp = (*env)->GetIntField(env, iphdr, fid);
	iph->ttl = tmp;
	
	
	iph->protocol = IPPROTO_UDP;
	iph->saddr = inet_addr ( source_ip );	//Spoof the source ip address
	iph->daddr = sin.sin_addr.s_addr;
		
	fid = (*env)->GetFieldID(env, ipClass, "calc_chkSum", "I");
        tmp = (*env)->GetIntField(env, iphdr, fid);
        if(tmp == 1) {
		iph->check = 0;		//Set to 0 before calculating checksum
		//Ip checksum
		iph->check = csum ((unsigned short *) datagram, iph->tot_len);	
	}
	else{
		fid = (*env)->GetFieldID(env, ipClass, "chkSum", "I");
        	tmp = (*env)->GetIntField(env, iphdr, fid);	
        	iph->check = tmp;
	}
	
	//UDP Header
	fid = (*env)->GetFieldID(env, udpClass, "sport", "I");
	int sport = (*env)->GetIntField(env, udphdr, fid);
	udph->source = htons (sport);
	udph->dest = htons (dport);
	
	fid = (*env)->GetFieldID(env, udpClass, "calc_len", "I");
	tmp = (*env)->GetIntField(env, udphdr, fid);
	if(tmp == 1){
		udph->len = htons(sizeof(struct udphdr) + strlen(data) );
	}
	else{
		fid = (*env)->GetFieldID(env, udpClass, "chkSum", "I");
		tmp = (*env)->GetIntField(env, udphdr, fid);
		udph->len = tmp;
	}
	
	fid = (*env)->GetFieldID(env, udpClass, "calc_chksum", "I");
	tmp = (*env)->GetIntField(env, udphdr, fid);
	if(tmp == 1){
		udph->check = 0;	//leave checksum 0 now, filled later by pseudo header
		
		//Now the UDP checksum
		psh.source_address = inet_addr( source_ip );
		psh.dest_address = sin.sin_addr.s_addr;
		psh.placeholder = 0;
		psh.protocol = IPPROTO_UDP;
		psh.udp_length = htons(sizeof(struct udphdr) + strlen(data) );
	
		int psize = sizeof(struct pseudo_header) + sizeof(struct udphdr) + strlen(data);
		pseudogram = malloc(psize);
	
		memcpy(pseudogram , (char*) &psh , sizeof (struct pseudo_header));
		memcpy(pseudogram + sizeof(struct pseudo_header) , udph , sizeof(struct udphdr) + strlen(data));
	
		udph->check = csum( (unsigned short*) pseudogram , psize);
	}
	else{
		fid = (*env)->GetFieldID(env, udpClass, "chkSum", "I");
		tmp = (*env)->GetIntField(env, udphdr, fid);
		udph->check = tmp;
	}
	
	//IP_HDRINCL to tell the kernel that headers are included in the packet
	int one = 1;
	const int *val = &one;
	int abc;
	
	if ((abc = setsockopt (s, IPPROTO_IP, IP_HDRINCL, val, sizeof (one))) < 0)
	{
		__android_log_print(ANDROID_LOG_INFO, "MYPROG", "errno = %d, %s", abc, strerror(abc));
		perror("Error setting IP_HDRINCL");
		return -2;
	}
	
	if (sendto (s, datagram, iph->tot_len ,	0, (struct sockaddr *) &sin, sizeof (sin)) < 0)
	{
		perror("sendto failed");
	}
	
	(*env)->ReleaseStringUTFChars(env,dataToSend, datasend);
	return 0;
}

