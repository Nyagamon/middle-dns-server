
#include "clSetting.h"
#include "clBlackList.h"
#include <winsock2.h>
#include <ws2tcpip.h>
#include <thread>
#pragma comment(lib,"ws2_32.lib")

clSetting setting;
clBlackList blacklist;

//
// ����������x���ɕϊ�
//
unsigned int domain_str2bin(unsigned char *bin,unsigned int size,const char *str){
	unsigned int len=0;
	if(size){
		for(const char *n;*str;str=n+1){
			n=strstr(str,".");
			unsigned char len2=n?n-str:(unsigned char)strlen(str);
			if(len+1+len2>size-1)break;
			*bin=len2;
			memcpy(&bin[1],str,len2);
			len+=1+len2;
			bin+=1+len2;
			if(!n)break;
		}
		*bin='\0';
		len+=1;
	}
	return len;
}

//
// ���x���𕶎���ɕϊ�
//
void domain_bin2str(char *str,unsigned int size,const unsigned char *bin){
	if(size){
		for(bool s=false;*bin;bin+=1+*bin){
			if(s){
				if(size<=1)break;
				*(str++)='.';
				size-=1;
			}else s=true;
			if(size<=*bin)break;
			memcpy(str,bin+1,*bin);
			str+=*bin;
			size-=*bin;
		}
		*str='\0';
	}
}

//
// IP�A�h���X�`�F�b�N
//
bool check_ip(const unsigned char *ip,const unsigned char *allow,const unsigned char *allow_mask,unsigned int size){
	for(unsigned int i=0;i<size;++i){
		if((ip[i]&allow_mask[i])!=(allow[i]&allow_mask[i]))return false;
	}
	return true;
};

//
// DNS�p�P�b�g���
//
unsigned int dns_analysis(unsigned char *data,unsigned int size,unsigned int max_size){

	// �T�C�Y�`�F�b�N
	if(size<12)return 0;

	// �N�G���`�F�b�N
	if(data[2]&0x80)return 0;
	if(*(unsigned short *)&data[4]==0)return 0;

	// �N�G���ȊO�̏����폜
	*(unsigned short *)&data[6]=0;
	*(unsigned short *)&data[8]=0;
	*(unsigned short *)&data[10]=0;

	// �T�C�Y�C��
	unsigned char *p=&data[12];
	for(int i=ntohs(*(unsigned short *)&data[4]);i>0;--i){
		for(;*p;p+=*p+1)if(*p&0xC0){++p;break;}p+=5;
	}
	size=p-data;

	// ���X�|���X�ݒ�
	data[2]|=0x80;
	data[3]|=0x80;

	// ���
	auto add=[&data,&size,&max_size](unsigned short offset,unsigned short type,unsigned int ttl,const void *src,unsigned short len){
		if(size+12+len<max_size){
			*(unsigned short *)&data[6]=htons(ntohs(*(unsigned short *)&data[6])+1);
			*(unsigned short *)&data[size]=htons(0xC000|offset);
			*(unsigned short *)&data[size+2]=htons(type);
			*(unsigned short *)&data[size+4]=htons(1);
			*(unsigned int *)&data[size+6]=htonl(ttl);
			*(unsigned short *)&data[size+10]=htons(len);
			if(src)memcpy(&data[size+12],src,len);
			else memset(&data[size+12],0,len);
			size+=12+len;
		}else{
			data[2]|=0x02;
		}
	};
	p=&data[12];
	for(int i=ntohs(*(unsigned short *)&data[4]);i>0;--i){

		// �h���C���ƃ^�C�v���擾
		char domain[0x200],*r=domain;
		int len=sizeof(domain);
		for(unsigned char *s=p;*s;){
			if(*s&0xC0){s=&data[ntohs(*(unsigned short *)s)&0x3FFF];continue;}
			if(len<=*s+1)break;
			memcpy(r,s,*s+1);
			r+=*s+1;len+=*s+1;
			s+=*s+1;
		}
		*r='\0';
		unsigned char *s=p;
		for(;*p;p+=*p+1)if(*p&0xC0){++p;break;}++p;
		int type=p[1];
		int offset=s-data;

		// �^�C�v�ʂɖ��O����
		if(type==1){
			if(blacklist.is_block(domain)){
				add(offset,type,setting.block_ttl(),nullptr,4);
			}else{
				char buf[0x200];
				domain_bin2str(buf,sizeof(buf),(unsigned char *)domain);
				addrinfo hints={},*res;
				hints.ai_flags=AI_CANONNAME;
				hints.ai_family=AF_INET;
				getaddrinfo(buf,nullptr,&hints,&res);
				for(addrinfo *ai=res;ai;ai=ai->ai_next){
					if(ai->ai_canonname){
						char buf2[0x200];
						int len=domain_str2bin((unsigned char *)buf2,sizeof(buf2),ai->ai_canonname);
						add(offset,5,setting.allow_ttl(),buf2,len);
						offset=size-len;
						if(blacklist.is_block(buf2)){
							add(offset,type,setting.block_ttl(),nullptr,4);
							break;
						}
					}
					if(blacklist.is_block(((sockaddr_in *)(ai->ai_addr))->sin_addr.S_un.S_addr)){
						add(offset,type,setting.block_ttl(),nullptr,4);
					}else{
						add(offset,type,setting.allow_ttl(),&((sockaddr_in *)(ai->ai_addr))->sin_addr.S_un.S_addr,4);
					}
				}
				freeaddrinfo(res);
			}
		}else if(type==28){
			if(blacklist.is_block(domain)){
				add(offset,type,setting.block_ttl(),nullptr,16);
			}else{
				char buf[0x200];
				domain_bin2str(buf,sizeof(buf),(unsigned char *)domain);
				addrinfo hints={},*res;
				hints.ai_flags=AI_CANONNAME;
				hints.ai_family=AF_INET6;
				getaddrinfo(buf,nullptr,&hints,&res);
				for(addrinfo *ai=res;ai;ai=ai->ai_next){
					if(ai->ai_canonname){
						char buf2[0x200];
						int len=domain_str2bin((unsigned char *)buf2,sizeof(buf2),ai->ai_canonname);
						add(offset,5,setting.allow_ttl(),buf2,len);
						offset=size-len;
						if(blacklist.is_block(buf2)){
							add(offset,type,setting.block_ttl(),nullptr,16);
							break;
						}
					}
					if(blacklist.is_block(((sockaddr_in6 *)(ai->ai_addr))->sin6_addr.u.Byte)){
						add(offset,type,setting.block_ttl(),nullptr,16);
					}else{
						add(offset,type,setting.allow_ttl(),&((sockaddr_in6 *)(ai->ai_addr))->sin6_addr.u.Byte,16);
					}
				}
				freeaddrinfo(res);
			}
		}

		p+=4;
	}
	return size;
}

//
// ���C��
//
int main(void){
	SetConsoleTitle(TEXT("DNS�T�[�o�["));

	// �ݒ��ǂݍ���
	setting.load("dns.ini");

	// �u���b�N���X�g��ǂݍ���
	blacklist.load(setting.blacklist_path());

	// ������
	WSAData wsa_data;
	WSAStartup(MAKEWORD(2,2),&wsa_data);

	std::thread ipv4_udp,ipv4_tcp,ipv6_udp,ipv6_tcp;
	if(setting.ipv4()){

		// �z�X�g���擾
		char hostname[256]={};
		gethostname(hostname,sizeof(hostname));

		// �z�X�gIP�A�h���X�擾
		IN_ADDR ipv4={};
		addrinfo hints={},*res;
		hints.ai_flags=AI_PASSIVE;
		hints.ai_family=AF_INET;
		getaddrinfo(hostname,nullptr,&hints,&res);
		for(addrinfo *ai=res;ai;ai=ai->ai_next){
			ipv4=((sockaddr_in *)(ai->ai_addr))->sin_addr;
			break;
		}
		freeaddrinfo(res);

		printf("DNS�T�[�o�[ IPv4\n");
		printf("IP�A�h���X: %d.%d.%d.%d (%s)\n",
			ipv4.S_un.S_un_b.s_b1,
			ipv4.S_un.S_un_b.s_b2,
			ipv4.S_un.S_un_b.s_b3,
			ipv4.S_un.S_un_b.s_b4,
			hostname);
		printf("���h���C��TTL: %d �b\n",setting.allow_ttl());
		printf("���ۃh���C��TTL: %d �b\n",setting.block_ttl());
		printf("\n");

		// UDP
		ipv4_udp=std::thread([&]{

			// UDP�|�[�g53�Ƀo�C���h
			SOCKET s=socket(AF_INET,SOCK_DGRAM,0);
			sockaddr_in addr;
			memset(&addr,0,sizeof(addr));
			addr.sin_family=AF_INET;
			addr.sin_port=htons(53);
			addr.sin_addr=ipv4;
			bind(s,(struct sockaddr *)&addr,sizeof(addr));

			// ��M�ҋ@
			unsigned char buf[0x200];
			do{
				int size=sizeof(addr);
				int len=recvfrom(s,(char *)buf,sizeof(buf),0,(struct sockaddr *)&addr,&size);
				if(len>0&&check_ip((unsigned char *)&addr.sin_addr.S_un.S_addr,setting.allow_ipv4(),setting.allow_ipv4_mask(),4)){
					len=dns_analysis(buf,len,sizeof(buf));
					if(len>0)sendto(s,(char *)buf,len,0,(struct sockaddr *)&addr,size);
				}
			}while(true);

			// ���
			closesocket(s);

		});

		// TCP
		ipv4_tcp=std::thread([&]{

			// TCP�|�[�g53�Ƀo�C���h
			SOCKET s=socket(AF_INET,SOCK_STREAM,0);
			sockaddr_in addr;
			memset(&addr,0,sizeof(addr));
			addr.sin_family=AF_INET;
			addr.sin_port=htons(53);
			addr.sin_addr=ipv4;
			bind(s,(struct sockaddr *)&addr,sizeof(addr));
			listen(s,1);

			// ��M�ҋ@
			unsigned char buf[0x4000];
			do{
				int size=sizeof(addr);
				SOCKET c=accept(s,(struct sockaddr *)&addr,&size);
				if(check_ip((unsigned char *)&addr.sin_addr.S_un.S_addr,setting.allow_ipv4(),setting.allow_ipv4_mask(),4)){
					int len=recv(c,(char *)buf,sizeof(buf),0);
					if(len>0){
						len=dns_analysis(buf,len,sizeof(buf));
						if(len>0)send(c,(char *)buf,len,0);
					}
				}
				closesocket(c);
			}while(true);

			// ���
			closesocket(s);

		});

	}

	if(setting.ipv6()){

		// �z�X�g���擾
		char hostname[256]={};
		gethostname(hostname,sizeof(hostname));

		// �z�X�gIP�A�h���X�擾
		IN6_ADDR ipv6={};
		addrinfo hints={},*res;
		hints.ai_flags=AI_PASSIVE;
		hints.ai_family=AF_INET6;
		getaddrinfo(hostname,nullptr,&hints,&res);
		for(addrinfo *ai=res;ai;ai=ai->ai_next){
			ipv6=((sockaddr_in6 *)(ai->ai_addr))->sin6_addr;
			//�O���[�o�����j�L���X�g�A�h���X
			//if(ipv6.u.Word[0]==htons(0x2001))break;
			//���j�[�N���[�J���A�h���X
			//if(ipv6.u.Byte[0]==0xFD)break;
			//�����N���[�J���A�h���X
			if(ipv6.u.Word[0]==htons(0xFE80))break;
		}
		freeaddrinfo(res);

		printf("DNS�T�[�o�[ IPv6\n");
		printf("IP�A�h���X: %x.%x.%x.%x.%x.%x.%x.%x (%s)\n",
			htons(ipv6.u.Word[0]),htons(ipv6.u.Word[1]),
			htons(ipv6.u.Word[2]),htons(ipv6.u.Word[3]),
			htons(ipv6.u.Word[4]),htons(ipv6.u.Word[5]),
			htons(ipv6.u.Word[6]),htons(ipv6.u.Word[7]),
			hostname);
		printf("���h���C��TTL: %d �b\n",setting.allow_ttl());
		printf("���ۃh���C��TTL: %d �b\n",setting.block_ttl());
		printf("\n");

		// UDP
		ipv6_udp=std::thread([&]{

			// UDP�|�[�g53�Ƀo�C���h
			SOCKET s=socket(AF_INET6,SOCK_DGRAM,0);
			sockaddr_in6 addr;
			memset(&addr,0,sizeof(addr));
			addr.sin6_family=AF_INET6;
			addr.sin6_port=htons(53);
			addr.sin6_addr=ipv6;
			bind(s,(struct sockaddr *)&addr,sizeof(addr));

			// ��M�ҋ@
			unsigned char buf[0x200];
			do{
				int size=sizeof(addr);
				int len=recvfrom(s,(char *)buf,sizeof(buf),0,(struct sockaddr *)&addr,&size);
				if(len>0&&check_ip(addr.sin6_addr.u.Byte,setting.allow_ipv6(),setting.allow_ipv6_mask(),16)){
					len=dns_analysis(buf,len,sizeof(buf));
					if(len>0)sendto(s,(char *)buf,len,0,(struct sockaddr *)&addr,size);
				}
			}while(true);

			// ���
			closesocket(s);

		});

		// TCP
		ipv6_tcp=std::thread([&]{

			// TCP�|�[�g53�Ƀo�C���h
			SOCKET s=socket(AF_INET6,SOCK_STREAM,0);
			sockaddr_in6 addr;
			memset(&addr,0,sizeof(addr));
			addr.sin6_family=AF_INET6;
			addr.sin6_port=htons(53);
			addr.sin6_addr=ipv6;
			bind(s,(struct sockaddr *)&addr,sizeof(addr));
			listen(s,5);

			// ��M�ҋ@
			unsigned char buf[0x4000];
			do{
				int size=sizeof(addr);
				SOCKET c=accept(s,(struct sockaddr *)&addr,&size);
				if(check_ip(addr.sin6_addr.u.Byte,setting.allow_ipv6(),setting.allow_ipv6_mask(),16)){
					int len=recv(c,(char *)buf,sizeof(buf),0);
					if(len>0){
						len=dns_analysis(buf,len,sizeof(buf));
						if(len>0)send(c,(char *)buf,len,0);
					}
				}
				closesocket(c);
			}while(true);

			// ���
			closesocket(s);

		});

	}

	// �ҋ@
	ipv4_udp.join();
	ipv4_tcp.join();
	ipv6_udp.join();
	ipv6_tcp.join();

	// ���
	WSACleanup();

	return 0;
}
