/* 
 * DFF -- An Open Source Digital Forensics Framework
 * Copyright (C) 2009-2013 ArxSys
 * 
 * This program is free software, distributed under the terms of
 * the GNU General Public License Version 2. See the LICENSE file
 * at the top of the source tree.
 * 
 * See http://www.digital-forensic.org for more information about this
 * project. Please do not directly contact any of the maintainers of
 * DFF for assistance; the project provides a web site, mailing lists
 * and IRC channels for your use.
 * 
 * Author(s):
 *  Christophe Malinge <cma@digital-forensic.org>
 *
 */

#ifndef __COMMON_HPP_
#define __COMMON_HPP_

/**
 * 0 : nothing
 * 3 : everything
 */
#define DEBUG_LEVEL	0
#define	VERBOSE		3
#define	INFO		2
#define CRITICAL	1
#if (!defined(WIN64) && !defined(WIN32))
#define DEBUG(level, str, args...) do {                                        \
  if (DEBUG_LEVEL)                                                             \
    if (level <= DEBUG_LEVEL)                                                  \
      printf("%s:%d\t" str, __FILE__, __LINE__, ##args);                       \
  } while (0)
#else
#define DEBUG(level, str, ...) do {                                            \
  if (DEBUG_LEVEL)                                                             \
    if (level <= DEBUG_LEVEL)                                                  \
      printf("%s:%d\t" str, __FILE__, __LINE__, __VA_ARGS__);                  \
  } while (0)
#endif

/**
 * Avoid sizeof(uint*_t) calls
 */
#define SIZE_BYTE	1
#define SIZE_2BYTES	2
#define SIZE_3BYTES	3
#define SIZE_4BYTES	4
#define SIZE_5BYTES	5
#define SIZE_6BYTES	6
#define SIZE_7BYTES	7
#define SIZE_8BYTES	8

#define BITS_IN_BYTE	8
#define BITS_IN_2BYTE	16
#define BITS_IN_3BYTE	24
#define BITS_IN_4BYTE	32
#define BITS_IN_5BYTE	40
#define BITS_IN_6BYTE	48
#define BITS_IN_7BYTE	56
#define BITS_IN_8BYTE   64


#endif // #defined __DEBUG_HPP_
