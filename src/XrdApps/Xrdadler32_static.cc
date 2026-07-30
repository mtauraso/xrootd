#define _FILE_OFFSET_BITS 64
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#include <fcntl.h>
#include <cerrno>

#if defined(__linux__) || defined(__GNU__) || (defined(__FreeBSD_kernel__) && defined(__GLIBC__))
#include <sys/xattr.h>
#endif

#include <zlib.h>

#include "XrdOuc/XrdOucString.hh"
#include "XrdCks/XrdCksXAttr.hh"
#include "XrdOuc/XrdOucXAttr.hh"

void fSetXattrAdler32(const char *path, int fd, const char* attr, char *value)
{
   XrdOucXAttr<XrdCksXAttr> xCS;
   struct stat st;

   if (fstat(fd, &st) || strlen(value) != 8) return;

   if (!xCS.Attr.Cks.Set("adler32") || !xCS.Attr.Cks.Set(value,8)) return;
   xCS.Attr.Cks.fmTime = static_cast<long long>(st.st_mtime);
   xCS.Attr.Cks.csTime = static_cast<int>(time(0) - st.st_mtime);
   xCS.Set("", fd);

#if defined(__linux__) || defined(__GNU__) || (defined(__FreeBSD_kernel__) && defined(__GLIBC__))
   fremovexattr(fd, attr);
#elif defined(__solaris__)
   int attrfd;
   attrfd = openat(fd, attr, O_XATTR|O_RDONLY);
   if (attrfd >= 0)
      {unlinkat(attrfd, attr, 0); close(attrfd);}
#endif
}

int fGetXattrAdler32(int fd, const char* attr, char *value)
{
   struct stat st;
   char mtime[12], attr_val[25], *p;
   int rc;

   if (fstat(fd, &st)) return 0;
   sprintf(mtime, "%lld", (long long) st.st_mtime);

#if defined(__linux__) || defined(__GNU__) || (defined(__FreeBSD_kernel__) && defined(__GLIBC__))
   rc = fgetxattr(fd, attr, attr_val, 25);
#elif defined(__solaris__)
   int attrfd;
   attrfd = openat(fd, attr, O_XATTR|O_RDONLY);
   if (attrfd < 0) return(0);
   rc = read(attrfd, attr_val, 25);
   close(attrfd);
#else
   return(0);
#endif

   if (rc == -1 || attr_val[8] != ':') return(0);
   attr_val[8] = '\0';
   attr_val[rc] = '\0';
   p = attr_val + 9;
   if (strcmp(p, mtime)) return(0);
   strcpy(value, attr_val);
   return(strlen(value));
}

int fGetXattrAdler32(const char *path, int fd, const char* attr, char *value)
{
   XrdOucXAttr<XrdCksXAttr> xCS;
   struct stat st;

   if (!xCS.Attr.Cks.Set("adler32") || xCS.Get(path, fd) <= 0
       || strcmp(xCS.Attr.Cks.Name, "adler32"))
      {int rc = fGetXattrAdler32(fd, attr, value);
       if (rc == 8) fSetXattrAdler32(path, fd, attr, value);
       return rc;
      }

   if (fstat(fd, &st)
   ||  xCS.Attr.Cks.fmTime != static_cast<long long>(st.st_mtime)) return 0;
   xCS.Attr.Cks.Get(value, 9);
   return 8;
}

#define N 1024*1024 /* reading block size */

int main(int argc, char *argv[])
{
   char path[2048], buf[N], adler_str[9];
   const char attr[] = "user.checksum.adler32";
   struct stat stbuf;
   int fd, len;
   uLong adler;

   adler = adler32(0L, Z_NULL, 0);

   if (argc == 2 && ! strcmp(argv[1], "-h"))
   {
      printf("Usage: %s file. Calculating adler32 checksum of a given local file.\n", argv[0]);
      printf("A file can be a local file or stdin (if omitted). Remote root:// URLs are not supported by this static build.\n");
      return 0;
   }

   if (argc > 1)
   {
      strcpy(path, argv[1]);
      if ((fd = open(path, O_RDONLY)) < 0 || fstat(fd, &stbuf) != 0 || !S_ISREG(stbuf.st_mode))
      {
         if (fd != -1)
            close(fd);
         printf("Error opening %s: %s\n", path, strerror(errno));
         return 1;
      }
      else /* see if the adler32 is saved in attribute already */
         if (fGetXattrAdler32(path, fd, attr, adler_str) == 8)
         {
            printf("%s %s\n", adler_str, path);
            return 0;
         }
   }
   else
   {
      fd = STDIN_FILENO;
      strcpy(path, "-");
   }

   while ( (len = read(fd, buf, N)) > 0 )
      adler = adler32(adler, (const Bytef*)buf, len);

   if (fd != STDIN_FILENO)
   { /* try saving adler32 to attribute before close() */
      sprintf(adler_str, "%08lx", adler);
      fSetXattrAdler32(path, fd, attr, adler_str);
      close(fd);
   }

   printf("%08lx %s\n", adler, path);
   return 0;
}
