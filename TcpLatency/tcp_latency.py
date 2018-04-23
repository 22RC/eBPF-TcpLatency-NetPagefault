#!/usr/bin/env python
from __future__ import print_function
from bcc import BPF
from socket import inet_ntop, ntohs, AF_INET, AF_INET6
import socket
from struct import pack
import ctypes as ct


b = BPF(src_file="tracelatency.c")
b.attach_kprobe(event="tcp_v4_connect", fn_name="trace_connect_entry") 
b.attach_kprobe(event="tcp_v6_connect", fn_name="trace_connect_entry")
b.attach_kretprobe(event="tcp_rcv_state_process", fn_name="trace_connect_return")
 

TASK_COMM_LEN = 16      # linux/sched.h

class Info_ipv4(ct.Structure):
    _fields_ = [
        ("pid", ct.c_ulonglong),
        ("saddr", ct.c_ulonglong),
        ("daddr", ct.c_ulonglong),
        ("dport", ct.c_ulonglong),
	("sport", ct.c_ulonglong),
        ("delta_us", ct.c_ulonglong),
        ("comm", ct.c_char * TASK_COMM_LEN)
    ]

class Info_ipv6(ct.Structure):
    _fields_ = [
        ("pid", ct.c_ulonglong),
        ("saddr", (ct.c_ulonglong * 2)),
        ("daddr", (ct.c_ulonglong * 2)),
        ("dport", ct.c_ulonglong),
	("sport", ct.c_ulonglong),
        ("delta_us", ct.c_ulonglong),
        ("comm", ct.c_char * TASK_COMM_LEN)
    ]


def event_v6(cpu, data, size):
    event = ct.cast(data, ct.POINTER(Info_ipv6)).contents
    addr = str(inet_ntop(AF_INET6, event.daddr))
    hostname, info = socket.getnameinfo((addr,0),0)
    host = socket.getfqdn(hostname)
    print('{:<5d} {:<15s} {:<37s} {:<24s} {:<5d} {:<5d} {:<12f}'.format(event.pid,event.comm.decode(),
        inet_ntop(AF_INET6, event.saddr), host, 
        event.dport,event.sport,
        float(event.delta_us)/1000 ))



def event_v4(cpu, data, size):
    event = ct.cast(data, ct.POINTER(Info_ipv4)).contents

    print('{:<5d} {:<15s} {:<37s} {:<24s} {:<5d} {:<5d} {:<12f}'.format(event.pid,
        event.comm.decode(),
        inet_ntop(AF_INET, pack("I", event.saddr)),
        inet_ntop(AF_INET, pack("I", event.daddr)), event.dport,event.sport,
        float(event.delta_us)/1000 ))

# header
print('{:<5s} {:<15s} {:<37s} {:<24s} {:<5s} {:<5s} {:<12s}'.format("PID", "COMM", "SADDR",
    "DADDR", "DPORT", "SPORT", "LAT(ms)"))

# read events
b["info_eventsv4"].open_perf_buffer(event_v4)
b["info_eventsv6"].open_perf_buffer(event_v6)
while 1:
    b.kprobe_poll()
