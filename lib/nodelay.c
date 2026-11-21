#define _GNU_SOURCE
#include <linux/bpf.h>
#include <sys/syscall.h>
#include <sys/socket.h>
#include <sys/resource.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <unistd.h>
#include <fcntl.h>
#include <stdint.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>

/* Linux SOCK_OPS helper; affects only the cgroup explicitly passed by Toolkit. */
static const char owned_name[] = "htk_nodelay";
static int bpf(enum bpf_cmd cmd, union bpf_attr *a) {
  return (int)syscall(__NR_bpf, cmd, a, sizeof(*a));
}
#define INS(code_, dst_, src_, off_, imm_) \
  ((struct bpf_insn){.code=(code_),.dst_reg=(dst_),.src_reg=(src_),.off=(off_),.imm=(imm_)})
#define MOV_REG(d,s) INS(BPF_ALU64|BPF_MOV|BPF_X,d,s,0,0)
#define MOV_IMM(d,i) INS(BPF_ALU64|BPF_MOV|BPF_K,d,0,0,i)

static int load_program(void) {
  /* Only established TCP callbacks in the attached rpxy cgroup are affected. */
  struct bpf_insn code[] = {
    MOV_REG(BPF_REG_6,BPF_REG_1),
    INS(BPF_LDX|BPF_W|BPF_MEM,BPF_REG_2,BPF_REG_6,offsetof(struct bpf_sock_ops,op),0),
    INS(BPF_JMP|BPF_JEQ|BPF_K,BPF_REG_2,0,1,BPF_SOCK_OPS_ACTIVE_ESTABLISHED_CB),
    INS(BPF_JMP|BPF_JNE|BPF_K,BPF_REG_2,0,8,BPF_SOCK_OPS_PASSIVE_ESTABLISHED_CB),
    INS(BPF_ST|BPF_W|BPF_MEM,BPF_REG_10,0,-4,1),
    MOV_REG(BPF_REG_1,BPF_REG_6),
    MOV_IMM(BPF_REG_2,IPPROTO_TCP),
    MOV_IMM(BPF_REG_3,TCP_NODELAY),
    MOV_REG(BPF_REG_4,BPF_REG_10),
    INS(BPF_ALU64|BPF_ADD|BPF_K,BPF_REG_4,0,0,-4),
    MOV_IMM(BPF_REG_5,4),
    INS(BPF_JMP|BPF_CALL,0,0,0,BPF_FUNC_setsockopt),
    MOV_IMM(BPF_REG_0,1),
    INS(BPF_JMP|BPF_EXIT,0,0,0,0),
  };
  char log[65536] = {0};
  union bpf_attr a = {0};
  a.prog_type=BPF_PROG_TYPE_SOCK_OPS;
  a.expected_attach_type=BPF_CGROUP_SOCK_OPS;
  a.insn_cnt=sizeof(code)/sizeof(code[0]);
  a.insns=(uint64_t)(uintptr_t)code;
  a.license=(uint64_t)(uintptr_t)"GPL";
  a.log_buf=(uint64_t)(uintptr_t)log;
  a.log_size=sizeof(log);a.log_level=1;
  memcpy(a.prog_name,owned_name,sizeof(owned_name));
  int fd=bpf(BPF_PROG_LOAD,&a);
  if(fd<0)fprintf(stderr,"BPF program load: %s\n%s\n",strerror(errno),log);
  return fd;
}
static int info(int fd, struct bpf_prog_info *i) {
  memset(i,0,sizeof(*i));union bpf_attr a={0};
  a.info.bpf_fd=fd;a.info.info_len=sizeof(*i);a.info.info=(uint64_t)(uintptr_t)i;
  return bpf(BPF_OBJ_GET_INFO_BY_FD,&a);
}
static int by_id(uint32_t id) {union bpf_attr a={0};a.prog_id=id;return bpf(BPF_PROG_GET_FD_BY_ID,&a);}
static int query(int cg,uint32_t *ids,uint32_t *n) {
  union bpf_attr a={0};a.query.target_fd=cg;a.query.attach_type=BPF_CGROUP_SOCK_OPS;
  a.query.prog_cnt=*n;a.query.prog_ids=(uint64_t)(uintptr_t)ids;
  int r=bpf(BPF_PROG_QUERY,&a);*n=a.query.prog_cnt;return r;
}
static int detach_one(int cg,int fd) {union bpf_attr a={0};a.target_fd=cg;a.attach_bpf_fd=fd;a.attach_type=BPF_CGROUP_SOCK_OPS;return bpf(BPF_PROG_DETACH,&a);}
int main(int argc,char **argv) {
  if(argc!=3 || (strcmp(argv[1],"attach") && strcmp(argv[1],"detach") && strcmp(argv[1],"status"))) {
    fprintf(stderr,"usage: %s attach|detach|status /sys/fs/cgroup/OWNED_GROUP\n",argv[0]);return 2;
  }
  struct rlimit limit={RLIM_INFINITY,RLIM_INFINITY};(void)setrlimit(RLIMIT_MEMLOCK,&limit);
  int cg=open(argv[2],O_RDONLY|O_DIRECTORY|O_CLOEXEC);
  if(cg<0){perror("open cgroup");return 1;}
  uint32_t ids[128],n=128;
  if(query(cg,ids,&n)<0){perror("query cgroup programs");close(cg);return 1;}
  int newfd=-1,already=0,owned=0;
  struct bpf_prog_info proposed={0};
  if(!strcmp(argv[1],"attach")) {
    newfd=load_program();if(newfd<0){close(cg);return 1;}
    if(info(newfd,&proposed)<0){perror("new program info");close(newfd);close(cg);return 1;}
    for(uint32_t j=0;j<n;j++) {
      int fd=by_id(ids[j]);struct bpf_prog_info i;
      if(fd>=0){if(info(fd,&i)==0 && !strcmp((char*)i.name,owned_name) && !memcmp(i.tag,proposed.tag,sizeof(i.tag)))already=1;close(fd);}
    }
    if(!already) {
      union bpf_attr a={0};a.target_fd=cg;a.attach_bpf_fd=newfd;a.attach_type=BPF_CGROUP_SOCK_OPS;a.attach_flags=BPF_F_ALLOW_MULTI;
      if(bpf(BPF_PROG_ATTACH,&a)<0){perror("attach owned program");close(newfd);close(cg);return 1;}
    }
  }
  /* Remove only our older program or an explicitly requested owned attachment. */
  for(uint32_t j=0;j<n;j++) {
    int fd=by_id(ids[j]);struct bpf_prog_info i;
    if(fd<0)continue;
    if(info(fd,&i)==0 && !strcmp((char*)i.name,owned_name)) {
      if(!strcmp(argv[1],"detach") || (!strcmp(argv[1],"attach") && memcmp(i.tag,proposed.tag,sizeof(i.tag)))) {
        if(detach_one(cg,fd)<0){perror("detach owned program");close(fd);if(newfd>=0)close(newfd);close(cg);return 1;}
      }
    }
    close(fd);
  }
  n=128;if(query(cg,ids,&n)<0){perror("verify cgroup programs");if(newfd>=0)close(newfd);close(cg);return 1;}
  printf("{\"owned_program_ids\":[");
  for(uint32_t j=0;j<n;j++) {
    int fd=by_id(ids[j]);struct bpf_prog_info i;
    if(fd>=0){if(info(fd,&i)==0 && !strcmp((char*)i.name,owned_name)){printf("%s%u",owned?",":"",ids[j]);owned++;}close(fd);}
  }
  printf("],\"owned_attached\":%s,\"total_direct_programs\":%u}\n",owned?"true":"false",n);
  if(newfd>=0)close(newfd);
  close(cg);
  return (!strcmp(argv[1],"attach") && owned!=1) ? 1 : 0;
}
