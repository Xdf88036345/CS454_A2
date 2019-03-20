//
// Starter code for CS 454
// You SHOULD change this file
//
//

#include "rpc.h"
#include "fuse.h"
#include "rw_lock.h"
// You may need to change your includes depending on whether you use C or C++.

// Needed for stat.
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>

// Needed for errors.
#include <errno.h>

// Needed for string operations.
#include <cstring>

// Need malloc and free.
#include <cstdlib>

//stl
#include <set>
#include <map>
#include <string>

// You may want to include iostream or cstdio.h if you print to standard error. 
//#define PRINT_ERR

#ifdef PRINT_ERR
#include <cstdio> 
#endif

using namespace std;

// Global state server_persist_dir.
char *server_persist_dir = NULL;

set <string> in_open_write; 
map <string, rw_lock_t> f_lock;

// We need to operate on the path relative to the the server_persist_dir.
// This function returns a path that appends the given short path to the
// server_persist_dir. The character array is allocated on the heap, therefore
// it should be freed after use.
char* get_full_path(char *short_path) {
  int short_path_len = strlen(short_path);
  int dir_len = strlen(server_persist_dir);
  int full_len = dir_len + short_path_len + 1;

  char *full_path = (char*)malloc(full_len);

  // First fill in the directory.
  strcpy(full_path, server_persist_dir);
  // Then append the path.
  strcat(full_path, short_path);

  return full_path;
}

// The server implementation of getattr.
int watdfs_getattr(int *argTypes, void **args) {
  // Get the arguments.
  // The first argument is the path relative to the mountpoint.
  char *short_path = (char*)args[0];
  // The second argument is the stat structure, which should be filled in
  // by this function.
  struct stat *statbuf = (struct stat*)args[1];
  // The third argument is the return code, which will be 0, or -errno.
  int *ret = (int*)args[2];

  // Get the local file name, so we call our helper function which appends
  // the server_persist_dir to the given path.
  char *full_path = get_full_path(short_path);

  // Initially we set set the return code to be 0.
  *ret = 0;

  // Make the stat system call, which is the corresponding system call needed
  // to support getattr. You should make the stat system call here:

  // Let sys_ret be the return code from the stat system call.
  int sys_ret = stat(full_path, statbuf);

  // You should use the statbuf as an argument to the stat system call, but it
  // is currently unused.
  //(void)statbuf;

  if (sys_ret < 0) {
    // If there is an error on the system call, then the return code should
    // be -errno.
    *ret = -errno;
  }

  // Clean up the full path, it was allocated on the heap.
  free(full_path);

  // The RPC call should always succeed, so return 0.
  return 0;
}

int watdfs_fgetattr(int *argTypes, void **args) {
	
	struct stat *statbuf = (struct stat*)args[1];

	struct fuse_file_info *fi = (struct fuse_file_info*)args[2];
	int *ret = (int*)args[3];
  
	*ret = 0;

	int sys_ret = fstat(fi->fh, statbuf);
	
	if(sys_ret < 0) {
		*ret = -errno;
	}

	return 0;

}

int watdfs_mknod(int *argTypes, void **args) {
  
	char *short_path = (char*)args[0];
	mode_t mod = *(int*)args[1];
	dev_t dev = *(long*)args[2];
	int *ret = (int*)args[3];
  
	char *full_path = get_full_path(short_path);
	*ret = 0;
#ifdef PRINT_ERR
	{}//printf("MKNOD! %s\n", full_path);
#endif


	int sys_ret = mknod(full_path, mod, dev);
#ifdef PRINT_ERR
	{}//printf("sys_ret: %d\n", sys_ret);
#endif

	if(sys_ret < 0) {
		*ret = -errno;
	}

	free(full_path);
	return 0;
}

int watdfs_open(int *argTypes, void **args) {

	char *short_path = (char*)args[0];
	struct fuse_file_info *fi = (struct fuse_file_info*)args[1];
	int *ret = (int*)args[2];

	char *full_path = get_full_path(short_path);
	
	{}//printf("OPEN %s\n", full_path);

	*ret = 0;
	string string_path(short_path);
	
	if((fi->flags & 3) == O_RDWR) {

		if(in_open_write.count(string_path)) {
			*ret = -EACCES;
			free(full_path);
			return 0;
		}
	}

	int sys_ret = open(full_path, fi->flags);

	if(sys_ret < 0) 
		*ret = -errno;
	else {
		fi->fh = sys_ret;
		if((fi->flags & 3) == O_RDWR)
			in_open_write.insert(string_path);
		f_lock[string_path] = RW_LOCK_INITIALIZER;
		rw_lock_init(&f_lock[string_path]);
	}
	{}//printf("open ret %d\n", *ret);

	free(full_path);
	return 0;
}

int watdfs_release(int *argTypes, void **args) {
	
	char *short_path = (char*)args[0];
	struct fuse_file_info *fi = (struct fuse_file_info*)args[1];
	int *ret = (int*)args[2];
	
	//char *full_path = get_full_path(short_path);
	*ret = 0;

	int sys_ret = close(fi->fh);
	
	if(sys_ret < 0) 
		*ret = -errno;
	else {
		string string_path(short_path);
		if((fi->flags & 3) == O_RDWR) {
			in_open_write.erase(string_path);
		}
		rw_lock_destroy(&f_lock[string_path]);
	}

	//free(full_path);
	return 0;
}

int watdfs_rw_lock(int* argTypes, void **args) {
	char *short_path = (char*)args[0];
	int type = *(int*)args[1]; // 0:lock 1:unlock

	rw_lock_mode_t mode = 
		*(int*)args[2] == 0 ? RW_READ_LOCK : RW_WRITE_LOCK;
	
	string string_path(short_path);
	int ret;
	if(type == 0) {
		ret = rw_lock_lock(&f_lock[string_path], mode);
		{}//printf("LOCK %s %d\n", short_path, mode);
	}
	else {
		ret = rw_lock_unlock(&f_lock[string_path], mode);
		{}//printf("UNLOCK %s %d\n", short_path, mode);
	}

	if(ret != 0)
		{}//printf("LOCK ERROR %d\n",ret);

	return 0;
}

int watdfs_write(int *argTypes, void **args) {
	//char *short_path = (char*)args[0];
	char *buf = (char*)args[1];
	size_t size = *(long*)args[2]; 
	off_t offset = *(long*)args[3];
	struct fuse_file_info *fi = (struct fuse_file_info*)args[4];
	int *ret = (int*)args[5];

#ifdef PRINT_ERR
	{}//printf("write: %ld %ld\n",size,offset);
#endif
	
	//char *full_path = get_full_path(short_path);
	*ret = 0;

	int sys_ret = pwrite(fi->fh, buf, size, offset);
	
	if(sys_ret < 0)
	{
		*ret = -errno;
		return 0;
	}

	//free(full_path);
	*ret = sys_ret;
	return 0;
}

int watdfs_read(int *argTypes, void **args) {	
	//char *short_path = (char*)args[0];
	char *buf = (char*)args[1];
	size_t size = *(long*)args[2]; 
	off_t offset = *(long*)args[3];
	struct fuse_file_info *fi = (struct fuse_file_info*)args[4];
	int *ret = (int*)args[5];
	
	//char *full_path = get_full_path(short_path);
	*ret = 0;

	int sys_ret = pread(fi->fh, buf, size, offset);
	
	if(sys_ret < 0)
	{
		*ret = -errno;
		return 0;
	}

	//free(full_path);
	*ret = sys_ret;
	return 0;
}

int watdfs_truncate(int *argTypes, void **args) {	
	char *short_path = (char*)args[0];
	off_t newsize = *(long*)args[1]; 
	int *ret = (int*)args[2];
	
	char *full_path = get_full_path(short_path);
	*ret = 0;

	int sys_ret = truncate(full_path, newsize);
	
	if(sys_ret < 0)
		*ret = -errno;

	free(full_path);
	return 0;
}

int watdfs_fsync(int *argTypes, void **args) {
	//char *short_path = (char*)args[0];
	struct fuse_file_info *fi = (struct fuse_file_info*)args[1];
	int *ret = (int*)args[2];
	
	//char *full_path = get_full_path(short_path);
	*ret = 0;

	int sys_ret = fsync(fi->fh); 
	
	if(sys_ret < 0)
		*ret = -errno;

	//free(full_path);
	return 0;
}

int watdfs_utimens(int *argTypes, void **args) {
	char *short_path = (char*)args[0];
	struct timespec *ts = (struct timespec*)args[1];	
	int *ret = (int*)args[2];
	
	char *full_path = get_full_path(short_path);
	*ret = 0;

	int sys_ret = utimensat(0,full_path,ts,0); 
	
	if(sys_ret < 0)
		*ret = -errno;

	free(full_path);
	return 0;
}

// The main function of the server.
int main(int argc, char *argv[]) {
  // argv[1] should contain the directory where you should store data on the
  // server. If it is not present it is an error, that we cannot recover from.
  if (argc != 2) {
    // In general you shouldn't print to stderr or stdout, but it may be
    // helpful here for debugging. Important: Make sure you turn off logging
    // prior to submission!
    // See watdfs_client.c for more details
    // # ifdef PRINT_ERR
    // f{}//printf(stderr, "Usage: %s server_persist_dir\n", argv[0]);
    // Or if you prefer c++:
    // std::cerr << "Usaage:" << argv[0] << " server_persist_dir";
    // #endif
#ifdef PRINT_ERR
	{}//printf("bad argc\n");
#endif
    return -1;
  }
  // Store the directory in a global variable.
  server_persist_dir = argv[1];

  // Initialize the rpc library by calling rpcServerInit. You should call
  // rpcServerInit here:
  int ret = rpcServerInit();
  if (ret < 0)
  {
#ifdef PRINT_ERR
	{}//printf("prcSI ret:%d\n",ret);
#endif
	return ret;
  }

  // If there is an error with rpcServerInit, it maybe useful to have
  // debug-printing here, and then you should return.

  // Register your functions with the RPC library.
  // getattr
  {
      // There are 3 args for the function (see watdfs_client.c for more detail).
      int argTypes[4];
      // First is the path.
      argTypes[0] = (1 << ARG_INPUT) | (1 << ARG_ARRAY) | (ARG_CHAR << 16) | 1;
      // Note for arrays we can set the length to be anything  > 1.

      // The second argument is the statbuf.
      argTypes[1] = (1 << ARG_OUTPUT) | (1 << ARG_ARRAY) | (ARG_CHAR << 16) | 1;
      // The third argument is the retcode.
      argTypes[2] = (1 << ARG_OUTPUT) | (ARG_INT << 16);
      // Finally we fill in the null terminator.
      argTypes[3] = 0;

      // We need to register the function with the types and the name.
      ret = rpcRegister((char*)"getattr", argTypes, watdfs_getattr);
      if (ret < 0) {
        // It may be useful to have debug-printing here.
#ifdef PRINT_ERR
		{}//printf("getattr rpc Reg bad!\n");
#endif
        return ret;
      }
  }

  // fgetattr
  {
	  int argTypes[5];

      argTypes[0] = (1 << ARG_INPUT) | (1 << ARG_ARRAY) | (ARG_CHAR << 16) | 1;  //path
      argTypes[1] = (1 << ARG_OUTPUT) | (1 << ARG_ARRAY) | (ARG_CHAR << 16) | 1; //statbuf
      argTypes[2] = (1 << ARG_INPUT) | (1 << ARG_ARRAY) | (ARG_CHAR << 16) | 1;  //fi
      argTypes[3] = (1 << ARG_OUTPUT) | (ARG_INT << 16); //retcode
	  argTypes[4] = 0;

      ret = rpcRegister((char*)"fgetattr", argTypes, watdfs_fgetattr);
      if (ret < 0) {
#ifdef PRINT_ERR
		{}//printf("fgetattr rpc Reg bad!\n");
#endif
        return ret;
      }
  }

  //mknod
  {
	  int argTypes[5];

      argTypes[0] = (1 << ARG_INPUT) | (1 << ARG_ARRAY) | (ARG_CHAR << 16) | 1;  //path
      argTypes[1] = (1 << ARG_INPUT) | (ARG_INT << 16);      //mod
      argTypes[2] = (1 << ARG_INPUT) | (ARG_LONG << 16);  //dev
      argTypes[3] = (1 << ARG_OUTPUT) | (ARG_INT << 16); //retcode
	  argTypes[4] = 0;

      ret = rpcRegister((char*)"mknod", argTypes, watdfs_mknod);
      if (ret < 0) {
#ifdef PRINT_ERR
		{}//printf("mknod rpc Reg bad!\n");
#endif
        return ret;
      }
  }

  //open
  {
	  int argTypes[4];
      argTypes[0] = (1 << ARG_INPUT) | (1 << ARG_ARRAY) | (ARG_CHAR << 16) | 1;  //path
      argTypes[1] = (1 << ARG_INPUT) | (1 << ARG_OUTPUT) | (1 << ARG_ARRAY) | (ARG_CHAR << 16) | 1;  //fi
      argTypes[2] = (1 << ARG_OUTPUT) | (ARG_INT << 16); //retcode
	  argTypes[3] = 0;
      
	  ret = rpcRegister((char*)"open", argTypes, watdfs_open);
      if (ret < 0)
        return ret;
  }

  //release
  {
	  int argTypes[4];
      argTypes[0] = (1 << ARG_INPUT) | (1 << ARG_ARRAY) | (ARG_CHAR << 16) | 1;  //path
      argTypes[1] = (1 << ARG_INPUT) | (1 << ARG_ARRAY) | (ARG_CHAR << 16) | 1;  //fi
      argTypes[2] = (1 << ARG_OUTPUT) | (ARG_INT << 16); //retcode
	  argTypes[3] = 0;
      
	  ret = rpcRegister((char*)"release", argTypes, watdfs_release);
      if (ret < 0)
        return ret;
  }

  //write
  {
	int argTypes[7];
      argTypes[0] = (1 << ARG_INPUT) | (1 << ARG_ARRAY) | (ARG_CHAR << 16) | 1;  //path
      argTypes[1] = (1 << ARG_INPUT) | (1 << ARG_ARRAY) | (ARG_CHAR << 16) | 1;  //buf
      argTypes[2] = (1 << ARG_INPUT) | (ARG_LONG << 16) ;                        //size
      argTypes[3] = (1 << ARG_INPUT) | (ARG_LONG << 16) ;                        //offset
      argTypes[4] = (1 << ARG_INPUT) | (1 << ARG_ARRAY) | (ARG_CHAR << 16) | 1;  //fi
      argTypes[5] = (1 << ARG_OUTPUT) | (ARG_INT << 16); //retcode
	  argTypes[6] = 0;
	  
	  ret = rpcRegister((char*)"write", argTypes, watdfs_write);
      if (ret < 0)
        return ret;
  }

  //read
  {
	  int argTypes[7];
      argTypes[0] = (1 << ARG_INPUT) | (1 << ARG_ARRAY) | (ARG_CHAR << 16) | 1;  //path
      argTypes[1] = (1 << ARG_OUTPUT) | (1 << ARG_ARRAY) | (ARG_CHAR << 16) | 1; //buf
      argTypes[2] = (1 << ARG_INPUT) | (ARG_LONG << 16) ;                        //size
      argTypes[3] = (1 << ARG_INPUT) | (ARG_LONG << 16) ;                        //offset
      argTypes[4] = (1 << ARG_INPUT) | (1 << ARG_ARRAY) | (ARG_CHAR << 16) | 1;  //fi
      argTypes[5] = (1 << ARG_OUTPUT) | (ARG_INT << 16); //retcode
	  argTypes[6] = 0;
	  
	  ret = rpcRegister((char*)"read", argTypes, watdfs_read);
      if (ret < 0)
        return ret;
  }

  //truncate
  {
	  int argTypes[4];
      argTypes[0] = (1 << ARG_INPUT) | (1 << ARG_ARRAY) | (ARG_CHAR << 16) | 1;  //path
      argTypes[1] = (1 << ARG_INPUT) | (ARG_LONG << 16) ;                        //newsize
      argTypes[2] = (1 << ARG_OUTPUT) | (ARG_INT << 16); //retcode
	  argTypes[3] = 0;
	  
	  ret = rpcRegister((char*)"truncate", argTypes, watdfs_truncate);
      if (ret < 0)
        return ret;
  }

  //fsync
  {
	  int argTypes[4];
      argTypes[0] = (1 << ARG_INPUT) | (1 << ARG_ARRAY) | (ARG_CHAR << 16) | 1;  //path
      argTypes[1] = (1 << ARG_INPUT) | (1 << ARG_ARRAY) | (ARG_CHAR << 16) | 1;  //fi
      argTypes[2] = (1 << ARG_OUTPUT) | (ARG_INT << 16); //retcode
	  argTypes[3] = 0;
	  
	  ret = rpcRegister((char*)"fsync", argTypes, watdfs_fsync);
      if (ret < 0)
        return ret;
  }

  //utimens
  {
	  int argTypes[4];
      argTypes[0] = (1 << ARG_INPUT) | (1 << ARG_ARRAY) | (ARG_CHAR << 16) | 1;  //path
      argTypes[1] = (1 << ARG_INPUT) | (1 << ARG_ARRAY) | (ARG_CHAR << 16) | 1;  //ts
      argTypes[2] = (1 << ARG_OUTPUT) | (ARG_INT << 16); //retcode
	  argTypes[3] = 0;
	  
	  ret = rpcRegister((char*)"utimens", argTypes, watdfs_utimens);
      if (ret < 0)
		  return ret;

  }

  //rw_lock
  {
	  int argTypes[4];
	  argTypes[0] = (1 << ARG_INPUT) | (1 << ARG_ARRAY) | (ARG_CHAR << 16) | 1;//path
	  argTypes[1] = (1 << ARG_INPUT) | (ARG_INT << 16); //type
	  argTypes[2] = (1 << ARG_INPUT) | (ARG_INT << 16); //mode
	  
	  ret = rpcRegister((char*)"rw_lock", argTypes, watdfs_rw_lock);
      if (ret < 0)
		  return ret;
  }

  // Hand over control to the RPC library by calling rpcExecute. You should call
  // rpcExecute here:

  ret = rpcExecute();
  // rpcExecute could fail so you may want to have debug-printing here, and then
  // you should return.
#ifdef PRINT_ERR
  if(ret < 0)
	  {}//printf("rpc exec fail:%d\n", ret);
#endif
  return ret;
}
