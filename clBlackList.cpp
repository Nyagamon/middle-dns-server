#include "clBlackList.h"
#include <stdio.h>

//
// コンストラクタ/デストラクタ
//
clBlackList::clBlackList():_domain(),_ipv4(){}
clBlackList::~clBlackList(){}

//
// ロード
//
bool clBlackList::load(const char *path){

	// 読み込み
	char *buf=nullptr;
	unsigned int size;
	{
		FILE *fp;
		if(fopen_s(&fp,path,"rb"))return false;
		fseek(fp,0,SEEK_END);
		size=ftell(fp);
		buf=new char [1+size+1];
		if(!buf){fclose(fp);return false;}
		fseek(fp,0,SEEK_SET);
		fread(&buf[1],size,1,fp);
		buf[1+size]='\0';
		fclose(fp);
	}

	// 解析
	auto is_hostname=[](const char *s){
		for(;*s;++s)if((*s<'0'||*s>'9')&&*s!='.')return true;
		return false;
	};
	for(char *s=&buf[1],*n;*s;s=n){
		n=strstr(s,"\n");if(n)*(n++)='\0';else n=&buf[1+size];
		char *r=strstr(s,"\r");if(r)*r='\0';
		if(*s){
			if(is_hostname(s)){
				char *d=buf;
				for(char *p=s;*p;p=r){
					r=strstr(p,".");if(r)*(r++)='\0';else r=&buf[1+size];
					*d=(char)strlen(p);
					strcpy_s(&d[1],*d+1,p);
					d+=*d+1;
				}
				*d='\0';
				_domain.insert(buf);
			}else{
				unsigned int ip=0;
				while(true){
					ip|=atoi(s)&0xFF;
					s=strstr(s,".");
					if(!s)break;
					++s;
					ip<<=8;
				}
				_ipv4.insert(ip);
			}
		}
	}

	// 解放
	delete [] buf;

	return true;
}

//
// ブロックチェック
//
bool clBlackList::is_block(const char *hostname)const{
	if(*hostname){
		if(_domain.find(hostname)!=_domain.end())return true;
		return is_block(&hostname[*(unsigned char *)hostname+1]);
	}
	return false;
}
bool clBlackList::is_block(unsigned int ipv4)const{
	return _ipv4.find(ipv4)!=_ipv4.end();
}
bool clBlackList::is_block(unsigned char *ipv6)const{
	return false;
}
