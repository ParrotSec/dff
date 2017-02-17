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
 *  Frederic Baguelin <fba@digital-forensic.org>
 *  Solal Jacob <sja@digital-forensic.org>
 */
#include <iostream>
#include <iomanip>
#include <sstream>

#include "mfso.hpp"
#include "threading.hpp"
#include "cache.hpp"

mfso::mfso(std::string name): fso(name)
{
  this->__fdmanager = new FdManager();
  this->__fmCache = new FileMappingCache(20);
  this->__verbose = false;
}

mfso::~mfso()
{
}

FileMapping*		mfso::mapFile(Node* node)
{
  FileMapping*		fm;

  fm = this->__fmCache->find(node);
  if (fm == NULL)
  {
     fm = new FileMapping(node);
     node->fileMapping(fm);
     this->__fmCache->insert(fm);
  }

  return fm;
}

int32_t 	mfso::vopen(Node *node)
{
  fdinfo*		fi = NULL;
  int32_t		fd;

  if (node != NULL)
  {
     try
     {
        fi = new fdinfo;
        fi->offset = 0;
        fi->node = node;
        fd = this->__fdmanager->push(fi);
        return fd;
     }
     catch(...)
     {
       return (-1);
     }
  }
  else
    throw("Node null");
  return (-1);
}

std::string	hexlify(uint64_t val)
{
  std::ostringstream os;

  os << "0x" << std::hex << val;
  return os.str();
}

void			mfso::setVerbose(bool verbose)
{
  this->__verbose = verbose;
}

bool			mfso::verbose()
{
  return this->__verbose;
}

int32_t		mfso::readFromMapping(FileMapping* fm, fdinfo* fi, void* buff, uint32_t size)
{
  VFile*		vfile;
  chunk*		current;
  uint64_t		relativeoffset;
  uint32_t		currentread;
  uint32_t		totalread;
  bool			eof;
  uint32_t		relativesize;
  CacheContainer*	container;
  VFilePool&		vfilePool = VFilePool::instance(); //this->vfilePool ? 

  eof = false;
  totalread = 0;
   
  while ((totalread < size) && (!eof))
  {
      try
      {
	  current = fm->chunkFromOffset(fi->offset);
	  relativeoffset = current->originoffset + (fi->offset - current->offset);
	  if ((size - totalread) < (current->offset + current->size - fi->offset))
	    relativesize = size - totalread;
	  else
	    relativesize = current->offset + current->size - fi->offset;
	  if (current->origin != NULL)
          {
	      if (this->__verbose == true)
              {
		  std::cout << "[" << this->name << "] reading " << fi->node->absolute() << std::endl
			    << "   " << hexlify(fi->offset) << "-" << hexlify(fi->offset + relativesize)
			    << " mapped @ " << hexlify(relativeoffset) << "-" << hexlify(relativeoffset + relativesize)
			    << " in " << current->origin->absolute() << std::endl;
              }

              container = vfilePool.find(current->origin);
              if (container == NULL)
                vfile = current->origin->open();
              else
                vfile = (VFile*)container->content;
              //vfile = current->origin->open();

	      vfile->seek(relativeoffset);
	      if ((currentread = vfile->read(((uint8_t*)buff) + totalread, relativesize)) == 0)
		  eof = true;

              if (container != NULL)
                vfilePool.unused(container);
              else
                vfilePool.insert(vfile);
	      //vfile->close();
	      fi->offset += currentread;
	      totalread += currentread;
	  }
	  else if (current->size != 0)
	  {
	      memset((uint8_t*)buff+totalread, 0, relativesize);
	      if (this->__verbose == true)
              {
		  std::cout << "[" << this->name << "] reading " << fi->node->absolute() << std::endl
			    << "   " << hexlify(fi->offset) << "-" << hexlify(fi->offset + relativesize)
			    << " mapped @ " << hexlify(relativeoffset) << "-" << hexlify(relativeoffset + relativesize)
			    << " in shadow node" << std::endl;
              }
	      fi->offset += relativesize;
	      totalread += relativesize;
	  }
	  else
          {
	    throw("chunk is not valid");
	  }
      }
      catch(...)
      {
	  eof = true;
      }
  }
  return (totalread);
}


int32_t 	mfso::vread(int32_t fd, void *buff, uint32_t size)
{
  fdinfo*	fi;
  uint64_t	realsize;
  int32_t	bytesread;
  FileMapping*	fm = NULL;

  try
  {
    fi = this->__fdmanager->get(fd);
    if (fi->node != NULL)
      fm = this->mapFile(fi->node);
    if (fm != NULL)
    {
       uint64_t fileSize = fm->maxOffset();

       if (fi->node->size() <= fileSize)
       {
         if (size <= (fi->node->size() - fi->offset))
           realsize = size;
         else
           realsize = fi->node->size() - fi->offset;
       }
       else
       {
         if (size <= (fileSize - fi->offset))
           realsize = size;
         else
           realsize = fileSize - fi->offset;
       }
       bytesread = this->readFromMapping(fm, fi, buff, realsize);
       fm->delref();
       return bytesread;
    }
    else
    {
      return (0);
    }
  }
  catch(...)
  {
      //throw(vfsError("problem while reading file"));
  }
  if (fm)
    fm->delref();
  return (0);
}

uint64_t	mfso::vtell(int32_t fd)
{
  fdinfo*	fi;

  try
  {
    fi = this->__fdmanager->get(fd);
    return (fi->offset);
  }
  catch(vfsError e)
  {
    return ((uint64_t)-1);
  }
}

int32_t 	mfso::vwrite(int32_t fd, void *buff, unsigned int size)
{
	return (0);
}

int32_t 	mfso::vclose(int32_t fd)
{
  fdinfo*	fi;

  try
  {
     fi = this->__fdmanager->get(fd);
//     delete fi; ? 
     this->__fdmanager->remove(fd);
  }
  catch (vfsError e)
  {
     std::cout << "mfso::close vfserror " << e.error << std::endl;
  }
  return (0);
}

uint64_t	mfso::vseek(int32_t fd, uint64_t offset, int32_t whence)
{
  fdinfo*	fi;
  FileMapping*  fm;
  try
  {
     fi = this->__fdmanager->get(fd);
     fm = this->mapFile(fi->node);
     if (fm == NULL)
	throw std::string("can't allocate fm");
     if (whence == 0)
     {
       if (offset > fm->maxOffset())
       {
	 fm->delref();
         return ((uint64_t)-1);
       }
       else
         fi->offset = offset;
     }
     else if (whence == 1)
     {
       if ((fi->offset + offset) > fm->maxOffset())
       {
	 fm->delref();
         return ((uint64_t)-1);
       }
       else
         fi->offset += offset;
     }
     else if (whence == 2)
       fi->offset = fm->maxOffset();
     fm->delref();
     return (fi->offset);
  }
  catch(...)
  {
     std::cout << "problem while getting fd information" << std::endl;
  }
  if (fm != NULL)
    fm->delref();

  return ((uint64_t)-1);
}

uint32_t	mfso::status(void)
{
  return 0;
}
