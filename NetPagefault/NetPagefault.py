#!/usr/bin/env python
from __future__ import print_function
from bcc import BPF, PerfType , PerfSWConfig
from socket import inet_ntop, ntohs, AF_INET
from struct import pack
import signal
import socket
import argparse
import ctypes as ct
from time import sleep


# arguments
examples = """examples:
    ./NetPagefault.py                # trace all TCP/UDP accept()s, connect()s,
				       default running 1000 seconds
    ./NetPagefault.py -t 100         # trace all TCP/UDP accept()s, connect()s,
				       running for 100 seconds
"""
parser = argparse.ArgumentParser(
    description="Trace TCP/UDP socket connects, accepts and process pagefaults",
    formatter_class=argparse.RawDescriptionHelpFormatter,
    epilog=examples)
parser.add_argument("-t", "--time",
    help="trace for this seconds")
args = parser.parse_args()

def signal_ignore(signum,frame):
    print()

def get_key(list_of_keys,pid,comm):
    i = -1
    index = 0
    while index < len(list_of_keys) and i == -1:
        if list_of_keys[index][0] == pid and list_of_keys[index][2] == comm :
            i = index 
        index += 1
    return i

########################### eBPF programs #######################################
bT = BPF(src_file="source_TCPtracer.c")
bU= BPF(src_file="source_UDPtracer.c")


########################### TCP probe Connect ###################################


bT.attach_kprobe(event="tcp_v4_connect", fn_name="trace_connect_entryTCP")
bT.attach_kretprobe(event="tcp_v4_connect", fn_name="trace_tcp_connect")


############################ TCP/UDP probe Accept ###############################

bT.attach_kretprobe(event='inet_csk_accept',fn_name="trace_tcp_accept")
bU.attach_kretprobe(event="udp_recvmsg",fn_name="trace_udp_rcv")

########################### UDP probe Connect ###################################

bU.attach_kprobe(event="udp_sendmsg",fn_name="trace_connect_entryUDP")
bU.attach_kretprobe(event="udp_sendmsg", fn_name="trace_udp_connect")

########################### Pagefault probe #####################################

f = BPF(src_file="source_Procfault.c")
f.attach_perf_event(
    ev_type=PerfType.SOFTWARE, ev_config=PerfSWConfig.PAGE_FAULTS_MIN,
    fn_name="page_min_flt",sample_period=0,sample_freq=49)

#################################################################################

if args.time:
	print("Running for {} seconds or hit Ctrl-C to end.".format(args.time))
	timeRunning = args.time
else:	
	print("Running for {} seconds or hit Ctrl-C to end.".format(1000))
	timeRunning = 1000
try:
    sleep(float(timeRunning))
except KeyboardInterrupt:
    signal.signal(signal.SIGINT, signal_ignore)
    print(" ")

TASK_COMM_LEN = 16      # linux/sched.h
min_flt_count = {}      # process page fault dict
tcp_map_v4_connect = {} # tcp client side
udp_map_v4_connect = {} # udp client side
tcp_map_v4_accept = {}  # tcp server_side
udp_map_v4_accept = {}  # udp server_side


#TCP stats socket connect (client_side)
print("\n")
print('Tcp client side (sock.connect) :\n')
print('{:<5s} {:<5s} {:<18s} {:<15s} {:<15s} {:<5s}'.format("PID","IPVER","PROC_NAME","IPSOURCE","IPDEST","DPORT"))
for (k,v) in bT.get_table("ipv4_map_client").items():
    tcp_map_v4_connect[(k.pid, 4, k.comm, k.saddr, k.daddr, k.dport)] = v.value
keyslist = tcp_map_v4_connect.keys()
for i in keyslist:
	print('{:<5d} {:<5d} {:<18s} {:<15s} {:<15s} {:<5d}'.format(i[0],i[1],i[2],
		inet_ntop(AF_INET,pack("I",i[3])), inet_ntop(AF_INET,pack("I",i[4])),i[5]))

#TCP stats socket accept (server_side)
print(" \n")
print('Tcp server side (sock.accept) :\n')
print('{:<5s} {:<5s} {:<18s} {:<15s} {:<15s} {:<5s}'.format("PID","IPVER","PROC_NAME","IPSOURCE","IPDEST","LPORT"))
for (k,v) in bT.get_table("ipv4_map_serverTCP").items():
    tcp_map_v4_accept[(k.pid, 4, k.comm, k.saddr, k.daddr, k.lport)] = v.value
keyslist_acceptTCP = tcp_map_v4_accept.keys()
for i in keyslist_acceptTCP:
	print('{:<5d} {:<5d} {:<18s} {:<15s} {:<15s} {:<5d}'.format(i[0],i[1],i[2],
		inet_ntop(AF_INET,pack("I",i[3])), inet_ntop(AF_INET,pack("I",i[4])),i[5]))

#UDP stats socket accept (server_side)
print(" \n")
print('Udp server side (sock.accept) :\n')
print('{:<5s} {:<5s} {:<18s} {:<15s} {:<15s} {:<5s} '.format("PID","IPVER","PROC_NAME","IPSOURCE","IPDEST","LPORT"))
for (k,v) in bU.get_table("ipv4_map_serverUDP").items():
    udp_map_v4_accept[(k.pid, 4, k.comm, k.saddr, k.daddr, k.lport)] = v.value
keyslist_acceptUDP = udp_map_v4_accept.keys()
for i in keyslist_acceptUDP:
	print('{:<5d} {:<5d} {:<18s} {:<15s} {:<15s} {:<5d} '.format(i[0],i[1],i[2],
		inet_ntop(AF_INET,pack("I",i[3])), inet_ntop(AF_INET,pack("I",i[4])),i[5]))

#UDP stats socket connect (client_side)
print(" \n")
print('Udp client side (sock.connect) :\n')
print('{:<5s} {:<5s} {:<18s} {:<15s} {:<15s} {:<5s}'.format("PID","IPVER","PROC_NAME","IPSOURCE","IPDEST","DPORT"))
for (k,v) in bU.get_table("ipv4_map_client_UDP").items():
    udp_map_v4_connect[(k.pid, 4, k.comm, k.saddr, k.daddr, k.dport)] = v.value
keyslist_connectUDP = udp_map_v4_connect.keys()
for i in keyslist_connectUDP:
	print('{:<5d} {:<5d} {:<18s} {:<15s} {:<15s} {:<5d}'.format(i[0],i[1],i[2],
		inet_ntop(AF_INET,pack("I",i[3])), inet_ntop(AF_INET,pack("I",i[4])),i[5]))

print("\n")
for (k, v) in f.get_table('min_flt_table').items():
    idx_key = get_key(keyslist, k.pid , k.comm)
    version = 0
    if idx_key >= 0:
        keysTuple = keyslist[idx_key]
        saddr, daddr = keysTuple[3] , keysTuple[4]
        version = 4
    else:
        idx_key = get_key(keyslist_acceptTCP, k.pid , k.comm)
        version = 0
        if idx_key >= 0:
            keysTuple = keyslist_acceptTCP[idx_key]
            saddr, daddr = keysTuple[3] , keysTuple[4]
            version = 4
        else:
            idx_key = get_key(keyslist_acceptUDP, k.pid , k.comm)
            version = 0
            if idx_key >= 0:
                keysTuple = keyslist_acceptUDP[idx_key]
                saddr, daddr = keysTuple[3] , keysTuple[4]
                version = 4
    if version != 0:
        min_flt_count[(k.pid, k.comm)] = (v.value,version,saddr,daddr)
    
print("Page fault: \n")
print('{:<8s} {:<18s} {:<10s} {:<12s}'.format("PID","NAME","IPVER","MIN_FLT"))

for (k, v) in sorted(f.get_table('min_flt_table').items(), key= lambda (k,v): v.value,reverse=True): 
    try:
        (value,version,sa,da) = min_flt_count[(k.pid, k.comm)]
    except KeyError:
        version = 0
        
    if version != 0:
        print('{:<8d} {:<18s} {:<10d} {:<12d}'.format(
            k.pid, k.comm.decode(), version,
            value))    
    
