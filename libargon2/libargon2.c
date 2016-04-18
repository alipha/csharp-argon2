/*
* The MIT License (MIT)
*
* Copyright (c) 2016 Kevin Spinar (Alipha)
*
* Permission is hereby granted, free of charge, to any person obtaining a copy
* of this software and associated documentation files (the "Software"), to deal
* in the Software without restriction, including without limitation the rights
* to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
* copies of the Software, and to permit persons to whom the Software is
* furnished to do so, subject to the following conditions:
*
* The above copyright notice and this permission notice shall be included in all
* copies or substantial portions of the Software.
*
* THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
* IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
* FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
* AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
* LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
* OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
* SOFTWARE.
*/

#include "libargon2.h"
#include "encoding.h"

/**
* This file is simply to proxy the argon2 functions so that I export with dllexport
* without modifying the original argon2.h header
*/

int crypto_argon2_hash(const uint32_t t_cost, const uint32_t m_cost,
	const uint32_t parallelism, const void *pwd,
	const size_t pwdlen, const void *salt,
	const size_t saltlen, void *hash,
	const size_t hashlen, char *encoded,
	const size_t encodedlen, argon2_type type, const uint32_t version) 
{
	return argon2_hash(t_cost, m_cost, parallelism, pwd, pwdlen, salt, saltlen, hash, hashlen, encoded, encodedlen, type, version);
}

int crypto_argon2_verify(const char *encoded, const void *pwd,
	const size_t pwdlen, argon2_type type)
{
	return argon2_verify(encoded, pwd, pwdlen, type);
}

const char *crypto_argon2_error_message(int error_code)
{
	return argon2_error_message(error_code);
}

int crypto_decode_string(argon2_context *ctx, const char *str, argon2_type type)
{
	return decode_string(ctx, str, type);
}