#pragma once

class clSetting{
public:
	clSetting();
	const char *blacklist_path(void)const;
	bool ipv4(void)const;
	bool ipv6(void)const;
	const unsigned char *allow_ipv4(void)const;
	const unsigned char *allow_ipv4_mask(void)const;
	const unsigned char *allow_ipv6(void)const;
	const unsigned char *allow_ipv6_mask(void)const;
	unsigned int allow_ttl(void)const;
	unsigned int block_ttl(void)const;
	bool load(const char *path);
private:
	char _blacklist_path[0x200];
	bool _ipv4;
	bool _ipv6;
	unsigned char _allow_ipv4[4];
	unsigned char _allow_ipv4_mask[4];
	unsigned char _allow_ipv6[16];
	unsigned char _allow_ipv6_mask[16];
	unsigned int _allow_ttl;
	unsigned int _block_ttl;
};
