"""Host libc boundary for the new upstream main(); preserves the CLI Oracle assertions."""
from pathlib import Path
import sys
sys.path.insert(0,str(Path(__file__).resolve().parents[2]/'nomount/tools'))
import build_zip

LIBC = r'''
#include <unistd.h>
#include <fcntl.h>
#include <string.h>
#include <errno.h>
#include <dirent.h>
#include <sys/stat.h>
#include <time.h>
#include <limits.h>
#include <sys/xattr.h>
static long fixture_syscall(long n,const char*a,const char*b,const void*c,unsigned long d,long e){
 return sys5(n,(long)a,(long)b,(long)c,d,e);
}
static char*fixture_getcwd(char*p,size_t size){return sys3(SYS_GETCWD,(long)p,size,0)>0?p:NULL;}
static ssize_t fixture_write(int fd,const void*p,size_t size){return sys3(SYS_WRITE,fd,(long)p,size);}
static ssize_t fixture_getxattr(const char*p,const char*n,void*v,size_t size){return getxattr(p,n,v,size,0,0);}
static ssize_t fixture_fgetxattr(int fd,const char*n,void*v,size_t size){return fgetxattr(fd,n,v,size,0,0);}
#define fgetxattr fixture_fgetxattr
#define syscall fixture_syscall
#define SYS_add_key SYS_ADD_KEY
#define getcwd fixture_getcwd
#define write fixture_write
#define getxattr fixture_getxattr
#undef PATH_MAX
'''

def compose(pre,header,body,post):
    if 'int main(int argc, char **argv)' not in body:
        return pre+header.split('/* --- DEFS --- */',1)[1]+body.replace('#include "nm.h"','')+post
    header=build_zip.adapt_cli_header(header)
    header=header[header.index('/* --- DEFS --- */'):].replace('#endif // #ifndef NM_H','')
    body=body.replace('#include "nm.h"','').replace('int main(int argc, char **argv)','static int nm_cli_main(int argc, char **argv)',1)
    bridge='\nstatic void c_main(long*sp){sys1(SYS_EXIT,nm_cli_main((int)*sp,(char**)(sp+1)));}\n'
    return pre+LIBC+header+body+bridge+post
