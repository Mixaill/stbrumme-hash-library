#pragma once

/**
 * hmac.h
 *
 * Copyright (c) 2015 Stephan Brumme. All rights reserved.
 * Copyright (c) 2019 Mikhail Paulyshka
 *
 * see http://create.stephan-brumme.com/disclaimer.html
 *
 * based on http://tools.ietf.org/html/rfc2104
 * see also http://en.wikipedia.org/wiki/Hash-based_message_authentication_code
 */

#include <cstring>
#include <string>
#include <vector>

template <typename HashMethod>
class HMAC
{
public:
	HMAC(const std::string& key)
	{
		initialize(key.data(), key.size());
	}

	HMAC(const std::vector<uint8_t>& key)
	{
		initialize(key.data(), key.size());
	}

	HMAC(const void* key, size_t numKeyBytes)
	{
		initialize(key, numKeyBytes);
	}

	void Append(const std::string& data)
	{
		// inside = hash((usedKey ^ 0x36) + data)
		insideHasher.add(data.data(), data.size());
	}

	void Append(const std::vector<uint8_t>& data)
	{
		// inside = hash((usedKey ^ 0x36) + data)
		insideHasher.add(data.data(), data.size());
	}

	void Append(const void* data, size_t data_size)
	{
		// inside = hash((usedKey ^ 0x36) + data)
		insideHasher.add(data, data_size);
	}

	std::array<uint8_t, HashMethod::HashBytes> GetHashBytes()
	{
		return finalize().getHashBytes();
	}
	
	std::string GetHashString()
	{
		return finalize().getHashString();
	}
	
private:
	HashMethod insideHasher;

	/**
	 * Contains key xored by 0x36
	 */
	std::array<uint8_t, HashMethod::BlockSize> _keyin{};
	
	void initialize(const void* key, size_t numKeyBytes)
	{
		// adjust length of key: must contain exactly blockSize bytes
		if (numKeyBytes <= _keyin.size()) {
			// copy key
			memcpy(_keyin.data(), key, numKeyBytes);
		}
		else {
			// shorten key: usedKey = hashed(key)
			HashMethod keyHasher;
			keyHasher.add(key, numKeyBytes);

			auto hashed = keyHasher.getHashBytes();
			memcpy(_keyin.data(), hashed.data(), hashed.size());
		}

		// create initial XOR padding
		for (size_t i = 0; i < _keyin.size(); i++) {
			_keyin[i] ^= 0x36;
		}

		// inside = hash((usedKey ^ 0x36) + data)
		insideHasher.add(_keyin);
	}

	HashMethod finalize()
	{
		// undo keyins's previous 0x36 XORing and apply a XOR by 0x5C
		std::array<uint8_t, HashMethod::BlockSize> keyout{};
		for (size_t i = 0; i < _keyin.size(); i++) {
			keyout[i] = _keyin[i] ^ 0x5C ^ 0x36;
		}

		// hash((key ^ 0x5C) + hash((key ^ 0x36) + data))
		HashMethod finalHasher;
		finalHasher.add(keyout);
		finalHasher.add(insideHasher.getHashBytes());

		return finalHasher;
	}
};
