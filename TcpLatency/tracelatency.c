#include <uapi/linux/ptrace.h>
#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wtautological-compare"
#pragma clang diagnostic ignored "-Wenum-conversion"
#include <net/sock.h>
#pragma clang diagnostic pop
#include <net/inet_sock.h>
#include <bcc/proto.h>


struct data_connect_t {
	u32 pid;
	char comm[TASK_COMM_LEN];
    	u64 ts;
};

BPF_HASH(connect_latency_map, struct sock *, struct data_connect_t);

struct info_v4_t{
    u64 pid;
    u64 saddr;
    u64 daddr;
    u64 dport;
    u64 sport;
    u64 delta_us;
    char comm[TASK_COMM_LEN];
};

BPF_PERF_OUTPUT(info_eventsv4);

struct info_v6_t {
    u64 pid;
    u64 saddr[2];
    u64 daddr[2]; 
    u64 dport;
    u64 sport;
    u64 delta_us;
    char comm[TASK_COMM_LEN];
};
BPF_PERF_OUTPUT(info_eventsv6);

int trace_connect_return(struct pt_regs *ctx, struct sock *skp){
    //check if connect
    if(skp->sk_state !=  TCP_ESTABLISHED)
		return 0;
    struct data_connect_t *data;
    data = connect_latency_map.lookup(&skp);
    if (data == 0)
	return 0;
    u16 family = 0, sport = 0;
    family = skp->__sk_common.skc_family;
    sport = skp->__sk_common.skc_num;
    if (family == AF_INET){
	    struct info_v4_t info = {.pid = data->pid};
	    bpf_probe_read(&info.comm,sizeof(info.comm),&data->comm);
	    info.saddr = skp-> __sk_common.skc_rcv_saddr;
	    info.daddr = skp-> __sk_common.skc_daddr;
	    u16 dport = skp->__sk_common.skc_dport;
	    /*struct inet_sock *sockp = (struct inet_sock *)skp;
	    u16 sport = sockp->inet_sport;*/
	    info.sport = ntohs(sport);
	    info.dport = ntohs(dport);
	    u64 now = bpf_ktime_get_ns();
	    u64 delta = ( now - data->ts) / 1000;
	    info.delta_us = delta;
	    info_eventsv4.perf_submit(ctx, &info, sizeof(info));
	    }
    else{
	struct info_v6_t info = {.pid = data->pid};
	    bpf_probe_read(&info.comm,sizeof(info.comm),&data->comm);
	    bpf_probe_read(&info.saddr, sizeof(info.saddr),
			skp->__sk_common.skc_v6_rcv_saddr.in6_u.u6_addr32);
            bpf_probe_read(&info.daddr, sizeof(info.daddr),
            		skp->__sk_common.skc_v6_daddr.in6_u.u6_addr32);
	    u16 dport = skp->__sk_common.skc_dport;
	    /*struct inet_sock *sockp = (struct inet_sock *)skp;
	    u16 sport = sockp->inet_sport;*/
	    info.sport = ntohs(sport);
	    info.dport = ntohs(dport);
	    u64 now = bpf_ktime_get_ns();
	    u64 delta = ( now - data->ts) / 1000;
	    info.delta_us = delta;
	    info_eventsv6.perf_submit(ctx, &info, sizeof(info));
	}
    connect_latency_map.delete(&skp);
    return 0;
}


int trace_connect_entry(struct pt_regs *ctx, struct sock *sk){
    u32 pid = bpf_get_current_pid_tgid();
    struct data_connect_t data = {.pid = pid};
    bpf_get_current_comm(&data.comm, sizeof(data.comm));
    data.ts = bpf_ktime_get_ns();
    connect_latency_map.update(&sk,&data);
    return 0;
}

