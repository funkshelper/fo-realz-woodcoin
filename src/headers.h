// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-2012 The Bitcoin developers
// Distributed under the MIT/X11 software license, see the accompanying
// file license.txt or http://www.opensource.org/licenses/mit-license.php.

// Include boost/foreach here as it defines __STDC_LIMIT_MACROS on some systems.
#include <boost/foreach.hpp>
#ifndef __STDC_LIMIT_MACROS
#define __STDC_LIMIT_MACROS // to enable UINT64_MAX from stdint.h
#endif

#if (defined(__unix__) || defined(unix)) && !defined(USG)
#include <sys/param.h>  // to get BSD define
#endif
#ifdef MAC_OSX
#ifndef BSD
#define BSD 1
#endif
#endif
#include <openssl/buffer.h>
#include <openssl/ecdsa.h>
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <openssl/sha.h>
#include <openssl/ripemd.h>
#include <db_cxx.h>
#include <stdio.h>
#include <stdlib.h>
#include <time.h>
#include <math.h>
#include <limits.h>
#include <float.h>
#include <assert.h>
#include <iostream>
#include <sstream>
#include <string>
#include <vector>
#include <list>
#include <deque>
#include <map>

#include <sys/time.h>
#include <sys/resource.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <unistd.h>
#include <errno.h>
#include <net/if.h>
#include <ifaddrs.h>
#include <fcntl.h>
#include <signal.h>

#ifdef BSD
#include <netinet/in.h>
#endif


#include "serialize.h"
#include "uint256.h"
#include "util.h"
#include "bignum.h"
#include "base58.h"
#include "main.h"
#include "noui.h"
