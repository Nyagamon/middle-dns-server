#pragma once

#define CINTERFACE // XP‚ÅŽg‚¦‚é‚æ‚¤‚É‚·‚é‚½‚ß
#include <unordered_set>

class clBlackList{
public:
	clBlackList();
	~clBlackList();
	bool load(const char *path);
	bool is_block(const char *domain)const;
	bool is_block(unsigned int ipv4)const;
	bool is_block(unsigned char *ipv6)const;
private:
	std::unordered_set<std::string> _domain;
	std::unordered_set<unsigned int> _ipv4;
};
