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


#ifndef __THREADING_HPP__
#define __THREADING_HPP__

#include <stdexcept>
#include <map>
#include <vector>
#include "export.hpp"

#ifdef WIN32
  #define mutex_lock		EnterCriticalSection
  #define mutex_unlock		LeaveCriticalSection
  #define mutex_def(var)	CRITICAL_SECTION var
  #define mutex_init(var)  	InitializeCriticalSection(var)
  #define mutex_destroy(var)	DeleteCriticalSection(var)	
#else
  #include <pthread.h>
  #define mutex_lock 		pthread_mutex_lock
  #define mutex_unlock 		pthread_mutex_unlock
  #define mutex_def(var)	pthread_mutex_t	var	
  #define mutex_init(var)	pthread_mutex_init(var, NULL)
  #define mutex_destroy(var)	pthread_mutex_destroy(var)
#endif

namespace dff
{
  class Mutex
  {
  public:
    EXPORT Mutex();
    EXPORT ~Mutex();
    EXPORT Mutex(const Mutex& other);
    EXPORT void	lock();
    EXPORT void	release();
  private:
    mutex_def(__mutex); 
  };

  class ScopedMutex
  {
  public:
    EXPORT ScopedMutex(Mutex& mutex);
    EXPORT ~ScopedMutex();
  private:
    Mutex&	__mutex;
  };

  template< typename key, typename value >
  class map
  {
  public:
    EXPORT map() { }
    EXPORT ~map() 
    { 
      ScopedMutex locker(__mutex);
      internals.clear();
    }

    EXPORT value&	operator[](const key _k) 
    { 
      ScopedMutex	locker(__mutex);
      return internals[_k];
    }

    EXPORT bool exist(key _k)
    {
      ScopedMutex locker(__mutex);
      return internals.find(_k) != internals.end();
    }
    
    EXPORT bool	empty() const
    {
      ScopedMutex	locker(__mutex);
      return internals.empty();
    }

    EXPORT value	 get_value(key _k)
    {
       ScopedMutex	locker(__mutex);
       typename std::map<key, value>::iterator iv;
       iv = internals.find(_k);	
       if (iv != internals.end())
       {
	 return(value(iv->second));
       }
       throw std::string("Can't find value");
    }

    EXPORT const std::map< key, value > &	getInternals()
    {
      return internals;
    }

	EXPORT void erase(key _k)
	{
	  ScopedMutex locker(__mutex);
	  internals.erase(_k);
	  return ;
	}

  private:
    std::map< key, value >	internals;
    mutable Mutex		__mutex;
  };

  template< typename value >
  class vector
  {
  public:
    EXPORT vector() { }

    EXPORT ~vector() 
    { 
      ScopedMutex locker(__mutex);
      internals.clear();
    }

    EXPORT value&	operator[](unsigned int n) throw (std::out_of_range)
    {
      ScopedMutex     locker(__mutex);
      return internals[n];
    }

    EXPORT const value at(unsigned int idx) const
    {
      ScopedMutex locker(__mutex);
      return internals.at(idx);
    }
    
    EXPORT bool	empty() const
    {
      ScopedMutex	locker(__mutex);
      return internals.empty();
    }

    EXPORT unsigned int size() const
    {
      return internals.size();
    }

    EXPORT void	push_back(const value& val)
    {
      ScopedMutex	locker(__mutex);
      internals.push_back(val);
    }
  private:
    mutable Mutex		__mutex;
    std::vector< value >	internals;
  };
};

#endif
