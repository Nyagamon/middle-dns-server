
#include "clSetting.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int atoi16(const char *str){
	int r=0;
	bool s=(*str=='-');if(s)++str;
	for(;*str;++str){
		if(*str>='0'&&*str<='9')r=(r<<4)|(*str-'0');
		else if(*str>='A'&&*str<='F')r=(r<<4)|(*str-'A'+10);
		else if(*str>='a'&&*str<='f')r=(r<<4)|(*str-'a'+10);
		else break;
	}
	return s?-r:r;
}

//
// コンストラクタ/デストラクタ
//
clSetting::clSetting():
	_blacklist_path(),
	_ipv4(true),
	_ipv6(true),
	_allow_ipv4(),
	_allow_ipv4_mask(),
	_allow_ipv6(),
	_allow_ipv6_mask(),
	_allow_ttl(10*60),
	_block_ttl(24*60*60){
	strcpy_s(_blacklist_path,"blacklists.txt");
	unsigned char ipv4[4]={192,168,1,};
	memcpy_s(_allow_ipv4,sizeof(_allow_ipv4),ipv4,sizeof(ipv4));
	unsigned char ipv4_mask[4]={255,255,255,};
	memcpy_s(_allow_ipv4_mask,sizeof(_allow_ipv4_mask),ipv4_mask,sizeof(ipv4_mask));
	unsigned char ipv6[16]={0xFE,0x80,};
	memcpy_s(_allow_ipv6,sizeof(_allow_ipv6),ipv6,sizeof(ipv6));
	unsigned char ipv6_mask[16]={0xFF,0xC0,};
	memcpy_s(_allow_ipv6_mask,sizeof(_allow_ipv6_mask),ipv6_mask,sizeof(ipv6_mask));
}

//
// インターフェース
//
const char *clSetting::blacklist_path(void)const{return _blacklist_path;}
bool clSetting::ipv4(void)const{return _ipv4;}
bool clSetting::ipv6(void)const{return _ipv6;}
const unsigned char *clSetting::allow_ipv4(void)const{return _allow_ipv4;}
const unsigned char *clSetting::allow_ipv4_mask(void)const{return _allow_ipv4_mask;}
const unsigned char *clSetting::allow_ipv6(void)const{return _allow_ipv6;}
const unsigned char *clSetting::allow_ipv6_mask(void)const{return _allow_ipv6_mask;}
unsigned int clSetting::allow_ttl(void)const{return _allow_ttl;}
unsigned int clSetting::block_ttl(void)const{return _block_ttl;}

//
// ロード
//
bool clSetting::load(const char *path){

	// 読み込み
	char *buf=nullptr;
	unsigned int size;
	{
		FILE *fp;
		if(fopen_s(&fp,path,"rb"))return false;
		fseek(fp,0,SEEK_END);
		size=ftell(fp);
		buf=new char [size+1];
		if(!buf){fclose(fp);return false;}
		fseek(fp,0,SEEK_SET);
		fread(buf,size,1,fp);
		buf[size]='\0';
		fclose(fp);
	}

	// 解析
	auto is_hostname=[](const char *s){
		for(;*s;++s)if((*s<'0'||*s>'9')&&*s!='.')return true;
		return false;
	};
	for(char *s=buf,*n;*s;s=n){
		n=strstr(s,"\n");if(n)*(n++)='\0';else n=&buf[size];
		char *r=strstr(s,"\r");if(r)*r='\0';
		char *key=s;s=strstr(s,"=");if(s)*(s++)='\0';else continue;
		char *value=s;
		while(*key==' '||*key=='\t')++key;
		for(s=&key[strlen(key)-1];key<=s&&(*s==' '||*s=='\t');--s)*s='\0';
		while(*value==' '||*value=='\t')++value;
		for(s=&value[strlen(value)-1];value<=s&&(*s==' '||*s=='\t');--s)*s='\0';
		for(s=key;*s;++s)if(*s>='A'&&*s<='Z')*s=*s-'A'+'a';
		if(strcmp(key,"path")==0)strcpy_s(_blacklist_path,value);
		else if(strcmp(key,"ipv4")==0)_ipv4=strcmp(value,"true")==0;
		else if(strcmp(key,"ipv6")==0)_ipv6=strcmp(value,"true")==0;
		else if(strcmp(key,"allow_ipv4")==0){
			s=strstr(value,"/");if(s)*(s++)='\0';
			*(unsigned int *)_allow_ipv4_mask=0xFFFFFFFF>>(s?32-atoi(s):0);
			s=value;
			for(int i=0;i<4;++i){
				_allow_ipv4[i]=atoi(s);
				s=strstr(s,".");
				if(!s)break;
				++s;
			}
		}
		else if(strcmp(key,"allow_ipv6")==0){
			s=strstr(value,"/");if(s)*(s++)='\0';
			for(int i=0,v=s?atoi(s):128;i<16;++i,v-=8){
				_allow_ipv6_mask[i]=(v>=8)?0xFF:(v<=0)?0x00:0xFF<<(8-v);
			}
			//※このやり方だと、::を使ったときに最後がおかしくなる
			memset(_allow_ipv6,0,sizeof(_allow_ipv6));
			s=value;
			for(int i=0;i<16;){
				int v=atoi16(s);
				_allow_ipv6[i++]=(v>>8)&0xFF;
				_allow_ipv6[i++]=v&0xFF;
				s=strstr(s,".");
				if(!s)break;
				++s;
			}
		}
		else if(strcmp(key,"allow_ttl")==0)_allow_ttl=atoi(value);
		else if(strcmp(key,"block_ttl")==0)_block_ttl=atoi(value);
	}

	// 解放
	delete [] buf;

	return true;
}
