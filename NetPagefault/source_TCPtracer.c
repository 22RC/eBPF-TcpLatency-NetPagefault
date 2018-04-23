#include <uapi/linux/ptrace.h>
#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wtautological-compare"
#pragma clang diagnostic ignored "-Wenum-conversion"
#include <net/sock.h>
#include <net/inet_sock.h>
#pragma clang diagnostic pop
#include <bcc/proto.h>


//HASH MAP key = PID ; VAL = Sock
BPF_HASH(thisSockTCP, u32, struct sock *);

struct data_TCP {
	u32 pid;
	short ipver;
	u64 saddr;
	u64 daddr;
	u64 dport;
	char comm[TASK_COMM_LEN];
};

//HASH MAP TCP CONNECT
BPF_HASH(ipv4_map_client, struct data_TCP);

struct data_tcp_accept {
	u32 pid;
	short ipver;
	u64 saddr;
   	u64 daddr;
	u64 lport;
	char comm[TASK_COMM_LEN];
};
//HASH MAP TCP ACCEPT
BPF_HASH(ipv4_map_serverTCP, struct data_tcp_accept);


/*------------TCP--------------TCP--------------TCP----------
  -----------------------Handler-----------------------------*/


/*static inline function return connect sys*/
static inline int trace_connect_return(struct pt_regs *ctx, short ipver){
    int ret = PT_REGS_RC(ctx);
    u32 pid = bpf_get_current_pid_tgid();
    struct sock **skpp;
    skpp = thisSockTCP.lookup(&pid);
    if (skpp == 0) 
        return 0;   // manca sock_entry
    // dettagli
    struct sock *skp = *skpp;
    if (ret != 0)
	return 0;
    struct data_TCP data = {.pid = pid, .ipver = ipver};
    bpf_get_current_comm(&data.comm, sizeof(data.comm));
    data.saddr = skp-> __sk_common.skc_rcv_saddr;
    data.daddr = skp-> __sk_common.skc_daddr;
    u16 dport = skp->__sk_common.skc_dport;
    data.dport = ntohs(dport);
    u64 zero = 0, *val;
    if(ipver == 4){
        val = ipv4_map_client.lookup_or_init(&data, &zero);
        (*val) += 1;
    }
    thisSockTCP.delete(&pid);
	
    return 0;
}
/*TCP Connect entry*/
int trace_connect_entryTCP(struct pt_regs *ctx, struct sock *sk){
    u32 pid = bpf_get_current_pid_tgid();
    // aggiorno la map dei socket
    thisSockTCP.update(&pid, &sk);
    return 0;
}
//TCP connect return
int trace_tcp_connect(struct pt_regs *ctx){
    return trace_connect_return(ctx, 4);
}


/*syscall inet_accept match if UDP or TCP and set value*/
int trace_tcp_accept(struct pt_regs *ctx){
    struct sock *newsk = (struct sock *)PT_REGS_RC(ctx);
    u32 pid = bpf_get_current_pid_tgid();
    if (newsk == NULL)
        return 0;
    // check this is TCP or UDP
    u8 protocol = 0;
   // bpf_probe_read(&protocol, 1, (void *)((long)&newsk->__sk_common.skc_state));
    bpf_probe_read(&protocol, 1, (void *)((long)&newsk->sk_gso_max_segs) -3);
    if (protocol == 6){
    // pull in details
	    u16 family = 0, lport = 0;
	    bpf_probe_read(&family, sizeof(family), &newsk->__sk_common.skc_family);
	    bpf_probe_read(&lport, sizeof(lport), &newsk->__sk_common.skc_num);
	    if (family == AF_INET) {
		struct data_tcp_accept data4 = {.pid = pid, .ipver = 4};
		bpf_probe_read(&data4.saddr, sizeof(u32),
		    &newsk->__sk_common.skc_rcv_saddr);
		bpf_probe_read(&data4.daddr, sizeof(u32),
		    &newsk->__sk_common.skc_daddr);
		data4.lport = lport;
		bpf_get_current_comm(&data4.comm, sizeof(data4.comm));
	    	u64 zero = 0, *val;
		val = ipv4_map_serverTCP.lookup_or_init(&data4, &zero);
		(*val) += 1;
    		}
	}
    return 0;
}

