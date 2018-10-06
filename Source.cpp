
#include "clSetting.h"
#include "clBlackList.h"
#include <winsock2.h>
#include <ws2tcpip.h>
#include <thread>
#pragma comment(lib,"ws2_32.lib")

clSetting setting;
clBlackList blacklist;

//
// 文字列をラベルに変換
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
// ラベルを文字列に変換
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
// IPアドレスチェック
//
bool check_ip(const unsigned char *ip,const unsigned char *allow,const unsigned char *allow_mask,unsigned int size){
	for(unsigned int i=0;i<size;++i){
		if((ip[i]&allow_mask[i])!=(allow[i]&allow_mask[i]))return false;
	}
	return true;
};

//
// DNSパケット解析
//
unsigned int dns_analysis(unsigned char *data,unsigned int size,unsigned int max_size){

	// サイズチェック
	if(size<12)return 0;

	// クエリチェック
	if(data[2]&0x80)return 0;
	if(*(unsigned short *)&data[4]==0)return 0;

	// クエリ以外の情報を削除
	*(unsigned short *)&data[6]=0;
	*(unsigned short *)&data[8]=0;
	*(unsigned short *)&data[10]=0;

	// サイズ修正
	unsigned char *p=&data[12];
	for(int i=ntohs(*(unsigned short *)&data[4]);i>0;--i){
		for(;*p;p+=*p+1)if(*p&0xC0){++p;break;}p+=5;
	}
	size=p-data;

	// レスポンス設定
	data[2]|=0x80;
	data[3]|=0x80;

	// 解析
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

		// ドメインとタイプを取得
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

		// タイプ別に名前解決
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
// メイン
//
int main(void){
	SetConsoleTitle(TEXT("DNSサーバー"));

	// 設定を読み込み
	setting.load("dns.ini");

	// ブラックリストを読み込み
	blacklist.load(setting.blacklist_path());

	// 初期化
	WSAData wsa_data;
	WSAStartup(MAKEWORD(2,2),&wsa_data);

	std::thread ipv4_udp,ipv4_tcp,ipv6_udp,ipv6_tcp;
	if(setting.ipv4()){

		// ホスト名取得
		char hostname[256]={};
		gethostname(hostname,sizeof(hostname));

		// ホストIPアドレス取得
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

		printf("DNSサーバー IPv4\n");
		printf("IPアドレス: %d.%d.%d.%d (%s)\n",
			ipv4.S_un.S_un_b.s_b1,
			ipv4.S_un.S_un_b.s_b2,
			ipv4.S_un.S_un_b.s_b3,
			ipv4.S_un.S_un_b.s_b4,
			hostname);
		printf("許可ドメインTTL: %d 秒\n",setting.allow_ttl());
		printf("拒否ドメインTTL: %d 秒\n",setting.block_ttl());
		printf("\n");

		// UDP
		ipv4_udp=std::thread([&]{

			// UDPポート53にバインド
			SOCKET s=socket(AF_INET,SOCK_DGRAM,0);
			sockaddr_in addr;
			memset(&addr,0,sizeof(addr));
			addr.sin_family=AF_INET;
			addr.sin_port=htons(53);
			addr.sin_addr=ipv4;
			bind(s,(struct sockaddr *)&addr,sizeof(addr));

			// 受信待機
			unsigned char buf[0x200];
			do{
				int size=sizeof(addr);
				int len=recvfrom(s,(char *)buf,sizeof(buf),0,(struct sockaddr *)&addr,&size);
				if(len>0&&check_ip((unsigned char *)&addr.sin_addr.S_un.S_addr,setting.allow_ipv4(),setting.allow_ipv4_mask(),4)){
					len=dns_analysis(buf,len,sizeof(buf));
					if(len>0)sendto(s,(char *)buf,len,0,(struct sockaddr *)&addr,size);
				}
			}while(true);

			// 解放
			closesocket(s);

		});

		// TCP
		ipv4_tcp=std::thread([&]{

			// TCPポート53にバインド
			SOCKET s=socket(AF_INET,SOCK_STREAM,0);
			sockaddr_in addr;
			memset(&addr,0,sizeof(addr));
			addr.sin_family=AF_INET;
			addr.sin_port=htons(53);
			addr.sin_addr=ipv4;
			bind(s,(struct sockaddr *)&addr,sizeof(addr));
			listen(s,1);

			// 受信待機
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

			// 解放
			closesocket(s);

		});

	}

	if(setting.ipv6()){

		// ホスト名取得
		char hostname[256]={};
		gethostname(hostname,sizeof(hostname));

		// ホストIPアドレス取得
		IN6_ADDR ipv6={};
		addrinfo hints={},*res;
		hints.ai_flags=AI_PASSIVE;
		hints.ai_family=AF_INET6;
		getaddrinfo(hostname,nullptr,&hints,&res);
		for(addrinfo *ai=res;ai;ai=ai->ai_next){
			ipv6=((sockaddr_in6 *)(ai->ai_addr))->sin6_addr;
			//グローバルユニキャストアドレス
			//if(ipv6.u.Word[0]==htons(0x2001))break;
			//ユニークローカルアドレス
			//if(ipv6.u.Byte[0]==0xFD)break;
			//リンクローカルアドレス
			if(ipv6.u.Word[0]==htons(0xFE80))break;
		}
		freeaddrinfo(res);

		printf("DNSサーバー IPv6\n");
		printf("IPアドレス: %x.%x.%x.%x.%x.%x.%x.%x (%s)\n",
			htons(ipv6.u.Word[0]),htons(ipv6.u.Word[1]),
			htons(ipv6.u.Word[2]),htons(ipv6.u.Word[3]),
			htons(ipv6.u.Word[4]),htons(ipv6.u.Word[5]),
			htons(ipv6.u.Word[6]),htons(ipv6.u.Word[7]),
			hostname);
		printf("許可ドメインTTL: %d 秒\n",setting.allow_ttl());
		printf("拒否ドメインTTL: %d 秒\n",setting.block_ttl());
		printf("\n");

		// UDP
		ipv6_udp=std::thread([&]{

			// UDPポート53にバインド
			SOCKET s=socket(AF_INET6,SOCK_DGRAM,0);
			sockaddr_in6 addr;
			memset(&addr,0,sizeof(addr));
			addr.sin6_family=AF_INET6;
			addr.sin6_port=htons(53);
			addr.sin6_addr=ipv6;
			bind(s,(struct sockaddr *)&addr,sizeof(addr));

			// 受信待機
			unsigned char buf[0x200];
			do{
				int size=sizeof(addr);
				int len=recvfrom(s,(char *)buf,sizeof(buf),0,(struct sockaddr *)&addr,&size);
				if(len>0&&check_ip(addr.sin6_addr.u.Byte,setting.allow_ipv6(),setting.allow_ipv6_mask(),16)){
					len=dns_analysis(buf,len,sizeof(buf));
					if(len>0)sendto(s,(char *)buf,len,0,(struct sockaddr *)&addr,size);
				}
			}while(true);

			// 解放
			closesocket(s);

		});

		// TCP
		ipv6_tcp=std::thread([&]{

			// TCPポート53にバインド
			SOCKET s=socket(AF_INET6,SOCK_STREAM,0);
			sockaddr_in6 addr;
			memset(&addr,0,sizeof(addr));
			addr.sin6_family=AF_INET6;
			addr.sin6_port=htons(53);
			addr.sin6_addr=ipv6;
			bind(s,(struct sockaddr *)&addr,sizeof(addr));
			listen(s,5);

			// 受信待機
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

			// 解放
			closesocket(s);

		});

	}

	// 待機
	ipv4_udp.join();
	ipv4_tcp.join();
	ipv6_udp.join();
	ipv6_tcp.join();

	// 解放
	WSACleanup();

	return 0;
}
