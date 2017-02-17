/*
 * DFF -- An Open Source Digital Forensics Framework
 * Copyright (C) 2009-2013 ArxSys
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
 *  Solal J. <sja@digital-forensic.org>
 */

#ifndef __VTIME_HPP__
#define __VTIME_HPP__

#include "export.hpp"

#ifndef WIN32
	#include <stdint.h>
#elif _MSC_VER >= 1600
	#include <stdint.h>
#else
	#include "wstdint.h"
#endif

#include <time.h>

#include <stdlib.h>
#include <vector>
#include <string>
#include <iostream>
#include <sstream>

/**
 * Nanoseconds between 01.01.1601 and 01.01.1970
 *  Leap year :
 *   (year modulo 4 is 0 and year modulo 100 is not 0) or year modulo 400 is 0
 *  So, 1700, 1800 and 1900 are not leap years.
 *  ((1970 - 1601) * 365 + int((1970-1601) / 4) - 3) * 24 * 3600 * 10000000
*/

#if __WORDSIZE == 64
#define NANOSECS_1601_TO_1970   (uint64_t)(116444736000000000UL)
#else
#define NANOSECS_1601_TO_1970   (uint64_t)(116444736000000000ULL)
#endif

#define TIME_UNIX    0
#define TIME_MS_64   1

class vtime
{
private:
  void			__setFromDate(std::string date);
  void			__setFromTime(std::string time);
public:
  EXPORT		vtime();
  EXPORT 		vtime(int, int, int, int, int, int, int);
  EXPORT		vtime(uint16_t dos_time, uint16_t dos_date);//DOS 32 bits format 
  EXPORT		vtime(uint64_t value, int type);
  EXPORT		vtime(std::string ts);
  EXPORT bool		operator==(vtime* v);
  EXPORT bool		operator!=(vtime* v);
  EXPORT bool		operator>(vtime* v);
  EXPORT bool		operator<(vtime* v);
  EXPORT bool		operator>=(vtime* v);
  EXPORT bool		operator<=(vtime* v);
  EXPORT virtual	~vtime();
  int 			year;
  int 			month;
  int 			day;
  int 			hour;
  int 			minute;
  int 			second;
  int 			usecond;
  int			wday;
  int			yday;
  int			dst;
};

#endif

