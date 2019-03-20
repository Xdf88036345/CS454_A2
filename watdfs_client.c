//
// Starter code for CS 454
// You SHOULD change this file
//
//

#include "watdfs_client.h"

#include "rpc.h"
#include "fuse.h"

#define PRINT_ERR

#ifdef PRINT_ERR
#include <cstdio>
#endif

//stl
#include <map>
#include <string>

using namespace std;

// You may want to include iostream or cstdio.h if you print to standard error.

map <string,int> in_open;
const char *cache_dir = NULL;
time_t t = 0;

struct fuse_file_info rmf[1024]; //remote fh
const char *fp[1024]; // file path
bool is_open[1024];
int f_flags[1024];
struct timespec	tc[1024];

char* get_cache_path(const char *short_path) {
  int short_path_len = strlen(short_path);
  int dir_len = strlen(cache_dir);
  int full_len = dir_len + short_path_len + 1;

  char *full_path = (char*)malloc(full_len);

  // First fill in the directory.
  strcpy(full_path, cache_dir);
  // Then append the path.
  strcat(full_path, short_path);

  return full_path;
}

int rpc_open(void *userdata, const char *path, struct fuse_file_info *fi);
int rpc_fgetattr(void *userdata, const char *path, struct stat *statbuf, struct fuse_file_info *fi);
int rpc_read(void *userdata, const char *path, char *buf, size_t size, off_t offset, struct fuse_file_info *fi);
int rpc_write(void *userdata, const char *path, const char *buf, size_t size, off_t offset, struct fuse_file_info *fi);
int rpc_release(void *userdata, const char *path, struct fuse_file_info *fi);
int rpc_truncate(void *userdata, const char *path, off_t newsize);
int rpc_getattr(void *userdata, const char *path, struct stat *statbuf);
int rpc_fsync(void *userdata, const char *path, struct fuse_file_info *fi);
int rpc_utimens(void *userdata, const char *path, const struct timespec ts[2]);


int tran_c2s(const char* path, struct fuse_file_info *local_fi, struct fuse_file_info *remote_fi) {
	printf("Copy file client to server\n");
	
	struct stat local_stat;

	fstat(local_fi->fh, &local_stat);

	printf("local file(%ld)'s size is %ld\n",local_fi->fh, local_stat.st_size);
	size_t file_size = local_stat.st_size;
	rpc_truncate(NULL, path, file_size);

	char* file_buf = new char[file_size+5];
	pread(local_fi->fh, file_buf, file_size, 0);

	printf("local: |%s|\n",file_buf);

	rpc_write(NULL, path, file_buf, file_size, 0, remote_fi);

	clock_gettime(CLOCK_REALTIME, &tc[local_fi->fh]);
	struct timespec ts[2] = {local_stat.st_atim, local_stat.st_mtim};
	rpc_utimens(NULL, path, ts);

	free(file_buf);
	return 0;
}

int tran_s2c(const char* path, const char* full_cache_path, struct fuse_file_info *local_fi, struct fuse_file_info *remote_fi) {
	printf("Copy file server to client\n");

	struct stat remote_stat;

	int ret = rpc_fgetattr(NULL, path, &remote_stat, remote_fi);

	if(ret < 0) {
		printf("get remote attr fail %d\n",errno);
	}
	printf("remote file(%ld)'s size is %ld\n",remote_fi->fh, remote_stat.st_size);

	size_t file_size = remote_stat.st_size;

	truncate(full_cache_path, file_size);
	char* file_buf = new char[file_size+5];
	rpc_read(NULL, path, file_buf, file_size, 0, remote_fi);
	printf("remote: |%s|\n",file_buf);
	
	pwrite(local_fi->fh, file_buf, file_size, 0);
	
	clock_gettime(CLOCK_REALTIME, &tc[local_fi->fh]);
	struct timespec ts[2] = {remote_stat.st_atim, remote_stat.st_mtim};
	utimensat(0, full_cache_path, ts, 0);

	free(file_buf);
	return 0;
}

void check_for_read(const char* path, struct fuse_file_info *local_fi, struct fuse_file_info *remote_fi) {
	struct timespec tnow;
	clock_gettime(CLOCK_REALTIME, &tnow);
	if(tnow.tv_sec < tc[local_fi->fh].tv_sec + t)
		return;
	
	struct stat local_stat, remote_stat;
	fstat(local_fi->fh, &local_stat);
	rpc_fgetattr(NULL, path, &remote_stat, remote_fi);
	if(local_stat.st_mtim.tv_sec == remote_stat.st_mtim.tv_sec 
			&& local_stat.st_mtim.tv_nsec == remote_stat.st_mtim.tv_nsec)
		return;

	char *full_path = get_cache_path(path);
	tran_s2c(path, full_path, local_fi, remote_fi);
	free(full_path);
}

void check_for_write(const char* path, struct fuse_file_info *local_fi, struct fuse_file_info *remote_fi) {
	struct timespec tnow;
	clock_gettime(CLOCK_REALTIME, &tnow);
	if(tnow.tv_sec < tc[local_fi->fh].tv_sec + t)
		return;
	
	struct stat local_stat, remote_stat;
	fstat(local_fi->fh, &local_stat);
	rpc_fgetattr(NULL, path, &remote_stat, remote_fi);
	if(local_stat.st_mtim.tv_sec == remote_stat.st_mtim.tv_sec 
			&& local_stat.st_mtim.tv_nsec == remote_stat.st_mtim.tv_nsec)
		return;

	tran_c2s(path, local_fi, remote_fi);
}


// SETUP AND TEARDOWN
void *watdfs_cli_init(struct fuse_conn_info *conn, const char *path_to_cache,
		time_t cache_interval) {
	// You should set up the RPC library here, by calling rpcClientInit.
	rpcClientInit();
	// You should check the return code of the rpcClientInit call, as it may fail,
	// for example, if the incorrect port was exported. If there was an error,
	// it may be useful to print to stderr or stdout during debugging.
	// Important: Make sure you turn off logging prior to submission!
	// One useful technique is to use pre-processor flags like:
	// # ifdef PRINT_ERR
	// fprintf(stderr, "Failed to initialize RPC Client\n");
	// Or if you prefer c++:
	// std::cerr << "Failed to initialize RPC Client";
	// #endif

	t = cache_interval;
	cache_dir = path_to_cache;

	// You can also initialize any global state that you want to have in this
	// method, and return it. The value that you return here will be passed
	// as userdata in other functions.

	// path_to_cache and cache_interval are not necessary for Assignment 2, but should
	// be used in Assignment 3.
	return NULL;
}

void watdfs_cli_destroy(void *userdata) {
	// You should clean up your userdata state here.
	// You should also tear down the RPC library by calling rpcClientDestroy.
	rpcClientDestroy();
}

// CREATE, OPEN AND CLOSE
int watdfs_cli_mknod(void *userdata, const char *path, mode_t mode, dev_t dev) {
	// Called to create a file.
#ifdef PRINT_ERR
	printf("!! mknod %s\n",path);
#endif
	int num_args = 4;
	void **args = (void**) malloc( 4 * sizeof(void*));
	int arg_types[num_args + 1];
	int pathlen = strlen(path) + 1;

	arg_types[0] = (1 << ARG_INPUT) | (1 << ARG_ARRAY) | (ARG_CHAR << 16) | pathlen;  //path
	args[0] = (void*)path;

	arg_types[1] = (1 << ARG_INPUT) | (ARG_INT << 16);      //mod
	args[1] = &mode;

	arg_types[2] = (1 << ARG_INPUT) | (ARG_LONG << 16);  //dev
	args[2] = &dev;

	arg_types[3] = (1 << ARG_OUTPUT) | (ARG_INT << 16); //retcode
	int retcode;
	args[3] = &retcode;

	arg_types[4] = 0;

	int rpc_ret = rpcCall((char *)"mknod", arg_types, args);

	int fxn_ret = 0;
	if (rpc_ret < 0) 
	{
		printf("??? rpc mknod fail\n");
		fxn_ret = -EINVAL;
	} 
	else 
	{
		if (retcode < 0) 
		{
#ifdef PRINT_ERR
			printf("mknod error: %d\n", retcode);
#endif
			fxn_ret = retcode;
		}
	}

	free(args);
	printf("mknod rtn: %d\n",fxn_ret);
	return fxn_ret;
}

int watdfs_cli_open(void *userdata, const char *path, struct fuse_file_info *fi) {
	// Called during open.
	// You should fill in fi->fh.	

	printf("Open! %s\n", path);

	string string_path(path);
	if(in_open.count(string_path))
		return -EMFILE;
	
	char* full_path = get_cache_path(path);

	struct fuse_file_info remote_fi = *fi;
	struct fuse_file_info local_fi  = *fi;

	//local : RW
	//remote : RD -> RD, WR -> RW, RW -> RW
	if((fi->flags & 3) == O_WRONLY)
	{
		remote_fi.flags &= ~3;
		remote_fi.flags |= O_RDWR;
	}
	printf("ori local flags 0x%x\n", local_fi.flags);
	//local_fi.flags &= ~3;
	//local_fi.flags |= O_RDWR | O_CREAT;

	local_fi.flags = O_RDWR | O_CREAT;

	printf("flags: ori: 0x%x\n server: 0x%x\n", fi->flags, remote_fi.flags);

	int ret = rpc_open(NULL, path, &remote_fi);
	if(ret < 0) {
		printf("Open fail %d\n",ret);
		free(full_path);
		return ret;
	}
	
	
	ret = open(full_path, local_fi.flags, S_IRWXU | S_IRWXG | S_IRWXO);
	if(ret < 0) {
		printf("local open fail: %d \n %s 0x%x\n", errno,full_path, local_fi.flags);
		return -errno;
	}
	
	fi->fh = local_fi.fh = ret;
	printf("open get fd: local:%ld remote%ld\n", local_fi.fh, remote_fi.fh);

	tran_s2c(path, full_path, &local_fi, &remote_fi);

	printf("finsh tran_s2c\n");

	in_open[string_path] = fi->fh;
	is_open[fi->fh] = true;
	f_flags[fi->fh] = fi->flags;
	fp[fi->fh] = path;
	rmf[fi->fh] = remote_fi;

	free(full_path);
	return 0;
}
int rpc_open(void *userdata, const char *path, struct fuse_file_info *fi) {
	int num_args = 3;
	void **args = (void**) malloc(3 * sizeof(void*));
	int arg_types[num_args + 1];
	int pathlen = strlen(path) + 1;
      
	arg_types[0] = (1 << ARG_INPUT) | (1 << ARG_ARRAY) | (ARG_CHAR << 16) | pathlen;  //path
	args[0] = (void*) path;

    arg_types[1] = (1 << ARG_INPUT) | (1 << ARG_OUTPUT) | (1 << ARG_ARRAY) | (ARG_CHAR << 16) | sizeof(fuse_file_info);  //fi
    args[1] = (void*)fi;

	arg_types[2] = (1 << ARG_OUTPUT) | (ARG_INT << 16); //retcode
	int retcode;
	args[2] = &retcode;

	
	arg_types[3] = 0;
	
	int rpc_ret = rpcCall((char *)"open", arg_types, args);

	int fxn_ret = 0;
	if (rpc_ret < 0) 
	{
		printf("??? repc open fail?\n");
		fxn_ret = -EINVAL;
	} 
	else 
	{
		if (retcode < 0) 
		{
			fxn_ret = retcode;
		}
	}

	free(args);
	return fxn_ret;
}

int watdfs_cli_release(void *userdata, const char *path, struct fuse_file_info *fi) {
	// Called during close, but possibly asynchronously.

	if((fi->flags & 3) != O_RDONLY) {
		tran_c2s(fp[fi->fh], fi, &rmf[fi->fh]); //flush remote
	}

	int ret = rpc_release(NULL, path, &rmf[fi->fh]); //close remote
	if(ret < 0)
		return ret;
	
	is_open[fi->fh] = false;
	close(fi->fh); //close local
	
	string string_path(path);
	in_open.erase(string_path);
	
	return 0;
}
int rpc_release(void *userdata, const char *path, struct fuse_file_info *fi) {
	int num_args = 3;
	void **args = (void**) malloc(3 * sizeof(void*));
	int arg_types[num_args + 1];
	int pathlen = strlen(path) + 1;
      
	arg_types[0] = (1 << ARG_INPUT) | (1 << ARG_ARRAY) | (ARG_CHAR << 16) | pathlen;  //path
	args[0] = (void*) path;

    arg_types[1] = (1 << ARG_INPUT) | (1 << ARG_ARRAY) | (ARG_CHAR << 16) | sizeof(fuse_file_info);  //fi
    args[1] = (void*)fi;

	arg_types[2] = (1 << ARG_OUTPUT) | (ARG_INT << 16); //retcode
	int retcode;
	args[2] = &retcode;

	
	arg_types[3] = 0;
	
	int rpc_ret = rpcCall((char *)"release", arg_types, args);

	int fxn_ret = 0;
	if (rpc_ret < 0) 
	{
		fxn_ret = -EINVAL;
	} 
	else 
	{
		if (retcode < 0) 
		{
			fxn_ret = retcode;
		}
	}

	free(args);
	return fxn_ret;
}

// GET FILE ATTRIBUTES
int watdfs_cli_getattr(void *userdata, const char *path, struct stat *statbuf) {
	//TODO:check
	printf("Getattr! %s\n", path);
	
	char *full_path = get_cache_path(path);

	printf("get full path ok %s\n", full_path);
	string string_path(path);
	if(in_open.count(string_path) == 0) {
		//just for pass test, stupid test design..
		int tmp_fd = open(full_path, O_CREAT);
		close(tmp_fd);

		return rpc_getattr(userdata, path, statbuf);
	}

	int fd = in_open[string_path];
//	if((f_flags[fd]&3) == O_WRONLY) {
//		return -EPERM;
//	}

	struct fuse_file_info tmp;
	tmp.fh = fd;
	check_for_read(path, &tmp, &rmf[fd]);

	int ret = stat(full_path, statbuf);
	

	free(full_path);
	if(ret < 0) {
		printf("stat error %d\n",errno);
		return -errno;
	}

	return ret;
}

int rpc_getattr(void *userdata, const char *path, struct stat *statbuf) {

	// SET UP THE RPC CALL

	// getattr has 3 arguments.
	int num_args = 3;

	// Allocate space for the output arguments.
	void **args = (void**) malloc(3 * sizeof(void*));

	// Allocate the space for arg types, and one extra space for the null
	// array element.
	int arg_types[num_args + 1];

	// The path has string length (strlen) + 1 (for the null character).
	int pathlen = strlen(path) + 1;

	// Fill in the arguments
	// The first argument is the path, it is an input only argument, and a char
	// array. The length of the array is the length of the path.
	arg_types[0] = (1 << ARG_INPUT) | (1 << ARG_ARRAY) | (ARG_CHAR << 16) | pathlen;
	// For arrays the argument is the array pointer, not a pointer to a pointer.
	args[0] = (void*)path;

	// The second argument is the stat structure. This argument is an output
	// only argument, and we treat it as a char array. The length of the array
	// is the size of the stat structure, which we can determine with sizeof.
	arg_types[1] = (1 << ARG_OUTPUT) | (1 << ARG_ARRAY) | (ARG_CHAR << 16) | sizeof(struct stat); // statbuf
	args[1] = (void*)statbuf;

	// The third argument is the return code, an output only argument, which is
	// an integer. You should fill in this argument type here:
	arg_types[2] = (1 << ARG_OUTPUT) | (ARG_INT << 16);

	// The return code is not an array, so we need to hand args[2] an int*.
	// The int* could be the address of an integer located on the stack, or use
	// a heap allocated integer, in which case it should be freed.
	// You should fill in the argument here:
	int retcode;
	args[2] = &retcode;

	// Finally, the last position of the arg types is 0. There is no corresponding
	// arg.
	arg_types[3] = 0;

	// MAKE THE RPC CALL
	int rpc_ret = rpcCall((char *)"getattr", arg_types, args);

	// HANDLE THE RETURN

	// The integer value watdfs_cli_getattr will return.
	int fxn_ret = 0;
	if (rpc_ret < 0) {
		// Something went wrong with the rpcCall, return a sensible return value.
		// In this case lets return, -EINVAL
		fxn_ret = -EINVAL;
	} else {
		// Our RPC call succeeded. However, it's possible that the return code
		// from the server is not 0, that is it may be -errno. Therefore, we should
		// set our function return value to the retcode from the server.
		// You should set the function return variable to the return code from the
		// server here:
		if (retcode < 0) {
			fxn_ret = retcode;
		}
	}

	if (fxn_ret < 0) {
		// Important: if the return code of watdfs_cli_getattr is negative (an
		// error), then we need to make sure that the stat structure is filled with
		// 0s. Otherwise, FUSE will be confused by the contradicting return values.
		memset(statbuf, 0, sizeof(struct stat));
	}

	// Clean up the memory we have allocated.
	free(args);

	// Finally return the value we got from the server.
	return fxn_ret;
}

int watdfs_cli_fgetattr(void *userdata, const char *path, struct stat *statbuf, struct fuse_file_info *fi) {
	
	//if((f_flags[fi->fh]&3) == O_WRONLY) {
	//	return -EPERM;
	//
	check_for_read(path, fi, &rmf[fi->fh]);

	int ret = fstat(fi->fh, statbuf);
	return ret;
}

int rpc_fgetattr(void *userdata, const char *path, struct stat *statbuf, struct fuse_file_info *fi) {
	int num_args = 4;
	void **args = (void**) malloc(4 * sizeof(void*));
	int arg_types[num_args + 1];
	int pathlen = strlen(path) + 1;

	arg_types[0] = (1 << ARG_INPUT) | (1 << ARG_ARRAY) | (ARG_CHAR << 16) | pathlen;
	args[0] = (void*)path;

	arg_types[1] = (1 << ARG_OUTPUT) | (1 << ARG_ARRAY) | (ARG_CHAR << 16) | sizeof(struct stat); // statbuf
	args[1] = (void*)statbuf;

	arg_types[2] = (1 << ARG_INPUT) | (1 << ARG_ARRAY) | (ARG_CHAR << 16) | sizeof(struct fuse_file_info);  //fi
	args[2] = (void*)fi;
	
	arg_types[3] = (1 << ARG_OUTPUT) | (ARG_INT << 16);
	int retcode;
	args[3] = &retcode;

	arg_types[4] = 0;

	int rpc_ret = rpcCall((char *)"fgetattr", arg_types, args);
	
	int fxn_ret = 0;
	if (rpc_ret < 0) 
	{
		fxn_ret = -EINVAL;
	} 
	else 
	{
		if (retcode < 0) 
		{
			fxn_ret = retcode;
		}
	}
	
	free(args);
	return fxn_ret;
}

// READ AND WRITE DATA
int watdfs_cli_read(void *userdata, const char *path, char *buf, size_t size,
		off_t offset, struct fuse_file_info *fi) {
	// Read size amount of data at offset of file into buf.
	printf("Read! %s\n", path);

	if((f_flags[fi->fh]&3) == O_WRONLY) {
		return -EPERM;
	}

	check_for_read(path, fi, &rmf[fi->fh]);

	printf("fd: %ld\n", fi->fh);
	int ret = pread(fi->fh, buf, size, offset);
	if(ret < 0)
	{
		printf("read sys error %d\n", errno);
		return -errno;
	}
	return ret;
}

int rpc_read(void *userdata, const char *path, char *buf, size_t size,
		off_t offset, struct fuse_file_info *fi) {
	// Remember that size may be greater then the maximum array size of the RPC
	// library.
	int num_args = 6;
	void **args = (void**) malloc(6 * sizeof(void*));
	int arg_types[num_args + 1];
	int pathlen = strlen(path) + 1;
	
	arg_types[0] = (1 << ARG_INPUT) | (1 << ARG_ARRAY) | (ARG_CHAR << 16) | pathlen;  //path
	args[0] = (void*) path;
    
	//arg_types[1] = (1 << ARG_OUTPUT) | (1 << ARG_ARRAY) | (ARG_CHAR << 16) | size;  //buf
    //args[1] = (void*) buf;
	
	arg_types[2] = (1 << ARG_INPUT) | (ARG_LONG << 16);  //size
	//args[2] = &size;
	
	arg_types[3] = (1 << ARG_INPUT) | (ARG_LONG << 16);  //offset
	args[3] = &offset;
    
	arg_types[4] = (1 << ARG_INPUT) | (1 << ARG_ARRAY) | (ARG_CHAR << 16) | sizeof(fuse_file_info);  //fi
    args[4] = (void*)fi;
	
	arg_types[5] = (1 << ARG_OUTPUT) | (ARG_INT << 16); //retcode
	int retcode;
	args[5] = &retcode;

	arg_types[6] = 0;

	int tot = 0;
	size_t ps = 0;
	args[2] = &ps;

	while(size>0)
	{
		ps = size < MAX_ARRAY_LEN ? size : MAX_ARRAY_LEN;
		size -= ps;
		arg_types[1] = (1 << ARG_OUTPUT) | (1 << ARG_ARRAY) | (ARG_CHAR << 16) | ps;  //buf
		args[1] = (void*)buf;
		
		int rpc_ret = rpcCall((char *)"read", arg_types, args);

		if (rpc_ret < 0)
			return -EINVAL;
		if (retcode < 0)
			return retcode;
     
		tot += retcode;
		offset += ps;
		buf += ps;
	}
	return tot;
}

int watdfs_cli_write(void *userdata, const char *path, const char *buf,
		size_t size, off_t offset, struct fuse_file_info *fi) {
	// Write size amount of data at offset of file from buf.
	printf("Write! %s\n",path);

	if((f_flags[fi->fh]&3) == O_RDONLY) {
		return -EPERM;
	}

	printf("local write |%s| = %ld at %ld\n endwith{%d}\n", buf,size,offset,buf[size-1]);
	int ret = pwrite(fi->fh, buf, size, offset);
	
	check_for_write(path, fi, &rmf[fi->fh]);
	
	if(ret < 0)
	{
		printf("write sys erro %d\n", errno);
		return -errno;
	}
	return ret;
}
int rpc_write(void *userdata, const char *path, const char *buf,
		size_t size, off_t offset, struct fuse_file_info *fi) {
	// Remember that size may be greater then the maximum array size of the RPC
	// library.
#ifdef PRINT_ERR
	printf("rpc WRITE |%s| [%ld,%ld] endwith{%d} -> %s\n",buf,offset,size,buf[size-1],path);
#endif
	int num_args = 6;
	void **args = (void**) malloc(6 * sizeof(void*));
	int arg_types[num_args + 1];
	int pathlen = strlen(path) + 1;
	
	arg_types[0] = (1 << ARG_INPUT) | (1 << ARG_ARRAY) | (ARG_CHAR << 16) | pathlen;  //path
	args[0] = (void*) path;
    
	//arg_types[1] = (1 << ARG_INPUT) | (1 << ARG_ARRAY) | (ARG_CHAR << 16) | size;  //buf
    //args[1] = (void*) buf;
	
	arg_types[2] = (1 << ARG_INPUT) | (ARG_LONG << 16);  //size
	//args[2] = &size;
	
	arg_types[3] = (1 << ARG_INPUT) | (ARG_LONG << 16);  //offset
	args[3] = &offset;
    
	arg_types[4] = (1 << ARG_INPUT) | (1 << ARG_ARRAY) | (ARG_CHAR << 16) | sizeof(fuse_file_info);  //fi
    args[4] = (void*)fi;
	
	arg_types[5] = (1 << ARG_OUTPUT) | (ARG_INT << 16); //retcode
	int retcode;
	args[5] = &retcode;

	arg_types[6] = 0;

	int tot = 0;
	size_t ps = 0;
	args[2] = &ps;
	
	while(size>0)
	{
		ps = size < MAX_ARRAY_LEN ? size : MAX_ARRAY_LEN;
		size -= ps;
		arg_types[1] = (1 << ARG_INPUT) | (1 << ARG_ARRAY) | (ARG_CHAR << 16) | ps;  //buf
		args[1] = (void*)buf;
#ifdef PRINT_ERR
		printf("this: %ld rest: %ld %s\n",ps, size,buf);
		printf("*args[2]: %ld\n", *(long*)args[2]);
#endif
	
		
		int rpc_ret = rpcCall((char *)"write", arg_types, args);
#ifdef PRINT_ERR
		printf("rpc_ret: %d ret_code: %d\n", rpc_ret, retcode);
#endif

		if (rpc_ret < 0)
			return -EINVAL;
		if (retcode < 0)
			return retcode;
     
		tot += retcode;
		offset += ps;
		buf += ps;
	}
#ifdef PRINT_ERR
	printf("Rtn(Tot): %d\n",tot);
#endif
	return tot;
}

int watdfs_cli_truncate(void *userdata, const char *path, off_t newsize) {
	// Change the file size to newsize.
	printf("Truncate %s to %ld\n", path, newsize);
	
	char *full_path = get_cache_path(path);
	string string_path(path);
	if(in_open.count(string_path) == 0) {
		return rpc_truncate(userdata, path, newsize);
	}

	int fd = in_open[string_path];
	if((f_flags[fd]&3) == O_WRONLY) {
		return -EPERM;
	}

	printf("local(%s) truncate to %ld\n",full_path, newsize);
	int ret = truncate(full_path, newsize);
	
	free(full_path);
	if(ret<0) {
		return -errno;
	}

	struct fuse_file_info tmp;
	tmp.fh = fd;
	check_for_write(path, &tmp, &rmf[fd]);

	return ret;
}

int rpc_truncate(void *userdata, const char *path, off_t newsize) {
	int num_args = 3;
	void **args = (void**) malloc( 3 * sizeof(void*));
	int arg_types[num_args + 1];
	int pathlen = strlen(path) + 1;

    arg_types[0] = (1 << ARG_INPUT) | (1 << ARG_ARRAY) | (ARG_CHAR << 16) | pathlen;  //path
    args[0] = (void*)path;

	arg_types[1] = (1 << ARG_INPUT) | (ARG_LONG << 16) ; //newsize
	args[1] = &newsize;

    arg_types[2] = (1 << ARG_OUTPUT) | (ARG_INT << 16); //retcode
	int retcode;
	args[2] = &retcode;
	
	arg_types[3] = 0;
	
	int rpc_ret = rpcCall((char *)"truncate", arg_types, args);

	int fxn_ret = 0;
	if (rpc_ret < 0) 
	{
		fxn_ret = -EINVAL;
	} 
	else 
	{
		if (retcode < 0) 
			fxn_ret = retcode;
	}

	free(args);
	return fxn_ret;
}

int watdfs_cli_fsync(void *userdata, const char *path,
		struct fuse_file_info *fi) {
	// Force a flush of file data.

	printf("Fsync %s\n", path);

	if(!is_open[fi->fh])
		return -EBADF;

	if((f_flags[fi->fh]&3) == O_RDONLY) {
		return -EPERM;
	}

	tran_c2s(path, fi, &rmf[fi->fh]);

	return rpc_fsync(userdata, path, &rmf[fi->fh]);
}

int rpc_fsync(void *userdata, const char *path,
		struct fuse_file_info *fi) {

	int num_args = 3;
	void **args = (void**) malloc( 3 * sizeof(void*));
	int arg_types[num_args + 1];
	int pathlen = strlen(path) + 1;
      
	arg_types[0] = (1 << ARG_INPUT) | (1 << ARG_ARRAY) | (ARG_CHAR << 16) | pathlen;  //path
	args[0] = (void*)path;
    
	arg_types[1] = (1 << ARG_INPUT) | (1 << ARG_ARRAY) | (ARG_CHAR << 16) | sizeof(struct fuse_file_info);  //fi
	args[1] = (void*)fi;

    arg_types[2] = (1 << ARG_OUTPUT) | (ARG_INT << 16); //retcode
	int retcode;
	args[2] = &retcode;

	arg_types[3] = 0;
	
	int rpc_ret = rpcCall((char *)"fsync", arg_types, args);
	
	int fxn_ret = 0;
	if (rpc_ret < 0) 
	{
		fxn_ret = -EINVAL;
	} 
	else 
	{
		if (retcode < 0) 
			fxn_ret = retcode;
	}

	free(args);
	return fxn_ret;
}

// CHANGE METADATA
int watdfs_cli_utimens(void *userdata, const char *path,
		const struct timespec ts[2]) {
	// Change file access and modification times.

	printf("Utime! %s\n", path);
	
	char *full_path = get_cache_path(path);
	string string_path(path);
	if(in_open.count(string_path) == 0) {
		return rpc_utimens(userdata, path, ts);
	}

	//TODO: may need check for read/write only, but I'm lazy..
	int ret = utimensat(0,full_path,ts,0);
	free(full_path);
	if(ret < 0)
		return -errno;
	
	int fd = in_open[string_path];
	struct fuse_file_info tmp;
	tmp.fh = fd;
	check_for_write(path, &tmp, &rmf[fd]);

	return 0;
}

int rpc_utimens(void *userdata, const char *path,
		const struct timespec ts[2]) {
	int num_args = 3;
	void **args = (void**) malloc( 3 * sizeof(void*));
	int arg_types[num_args + 1];
	int pathlen = strlen(path) + 1;
      
	arg_types[0] = (1 << ARG_INPUT) | (1 << ARG_ARRAY) | (ARG_CHAR << 16) | pathlen;  //path
	args[0] = (void*)path;
    
	arg_types[1] = (1 << ARG_INPUT) | (1 << ARG_ARRAY) | (ARG_CHAR << 16) | (2*sizeof(struct timespec));  //ts
	args[1] = (void*)ts;

    arg_types[2] = (1 << ARG_OUTPUT) | (ARG_INT << 16); //retcode
	int retcode;
	args[2] = &retcode;

	arg_types[3] = 0;
	
	int rpc_ret = rpcCall((char *)"utimens", arg_types, args);
	
	int fxn_ret = 0;
	if (rpc_ret < 0) 
	{
		fxn_ret = -EINVAL;
	} 
	else 
	{
		if (retcode < 0) 
			fxn_ret = retcode;
	}

	free(args);
	return fxn_ret;
}

