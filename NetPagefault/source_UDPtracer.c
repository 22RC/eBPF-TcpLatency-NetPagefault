#include <uapi/linux/ptrace.h>
#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wtautological-compare"
#pragma clang diagnostic ignored "-Wenum-conversion"
#include <net/sock.h>
#pragma clang diagnostic pop


//HASH MAP key = PID ; VAL = Sock
BPF_HASH(thisSockUDP, u32, struct sock *);

struct data_UDP {
	u32 pid;
	short ipver;
	u64 saddr;
	u64 daddr;
	u64 dport;
	char comm[TASK_COMM_LEN];
};
//HASH MAP UDP CONNECT
BPF_HASH(ipv4_map_client_UDP, struct data_UDP);

struct data_udp_accept {
	u32 pid;
	short ipver;
	u64 saddr;
	u64 daddr;
	u64 lport;
	u64 dport;
	char comm[TASK_COMM_LEN];
};
//HASH MAP UDP ACCEPT
BPF_HASH(ipv4_map_serverUDP, struct data_udp_accept);


/*------------UDP--------------UDP--------------UDP----------
  -----------------------Handler-----------------------------*/


//UDP_rcvmsg
int trace_udp_rcv(struct pt_regs *ctx, struct sock *sk){
    u32 pid = bpf_get_current_pid_tgid();
    int ret = PT_REGS_RC(ctx); 
    if (sk == NULL || ret == -1)
        return 0;
    u16 lport = 0;
    lport = sk->__sk_common.skc_num;
    
    struct data_udp_accept data4 = {.pid = pid, .ipver = 4};
    data4.saddr = sk->__sk_common.skc_rcv_saddr;
    data4.daddr= sk->__sk_common.skc_daddr;
    data4.lport = ntohs(lport);
    bpf_get_current_comm(&data4.comm, sizeof(data4.comm));
    u64 zero = 0, *val;
    // if addresses or ports are 0, ignore
    if (data4.saddr == 0 || data4.daddr == 0 ||data4.lport == 0) 
    	return 0;
    val = ipv4_map_serverUDP.lookup_or_init(&data4, &zero);
    (*val) += 1;

return 0;
}


//UDP CONNECT return
int trace_udp_connect(struct pt_regs *ctx){
    int ret = PT_REGS_RC(ctx);   
    u32 pid = bpf_get_current_pid_tgid();
    struct sock **skpp;
    skpp = thisSockUDP.lookup(&pid);
    if (skpp == NULL || ret == -1) 
        return 0;   // not sock_entry or return not success
    struct sock *sk = *skpp;
    u64 dport = sk->__sk_common.skc_dport;
    if (dport == 0)
	return 0;
    struct data_UDP data = {.pid = pid, .ipver = 4};
    bpf_get_current_comm(&data.comm, sizeof(data.comm));
    data.saddr = sk-> __sk_common.skc_rcv_saddr;
    data.daddr = sk-> __sk_common.skc_daddr;
    data.dport = ntohs(dport);
    u64 zero = 0, *val;
    val = ipv4_map_client_UDP.lookup_or_init(&data, &zero);
    (*val) += 1;
    thisSockUDP.delete(&pid);
    return 0;
}
//UDP CONNECT entry
int trace_connect_entryUDP(struct pt_regs *ctx,struct sock *sk){
    u32 pid = bpf_get_current_pid_tgid();
    thisSockUDP.update(&pid, &sk);
    return 0;
}
