#!/usr/bin/python3
# -*- coding: utf-8 -*-
from struct import pack, unpack
from socket import socket, AF_INET, SOCK_STREAM, timeout
from hashlib import md5
from binascii import hexlify, unhexlify
from random import choice
from string import ascii_uppercase
import sys
import argparse


parser = argparse.ArgumentParser(description='Retrieve list of vhosts from RabbitMQ instance')

parser.add_argument('target', action='store', type=str, help='RabbitMQ node address or FQDN')
parser.add_argument('mode', action='store', type=str, help='Script mode (vhosts/queues)')
parser.add_argument('-p', type=str, default="", help='RabbitMQ vhost (queues mode only)')
parser.add_argument('--cookie', type=str, default="", help='RabbitMQ Erlang cookie')
parser.add_argument('--port', type=int, default=0, help='RabbitMQ Erlang TCP port')
args = parser.parse_args()


def rand_id(n=12):
    return (''.join([choice(ascii_uppercase) for c in range(n)]) + '@zabbix').encode('ascii')


def send_name(name):
    return pack('!HcHI', 7 + len(name), b'n', 5, 0x00077ffc) + name


def send_challenge_reply(cookie, challenge):
    m = md5()
    m.update(cookie.encode('ascii'))
    m.update(challenge.encode('ascii'))
    response = m.digest()
    return pack('!HcI', len(response)+5, b'r', 0) + response


def parse_vhost_recv(s):
    s.recv(6)
    atom_caches = s.recv(1)
    if atom_caches == b'\x08':
        gap = 32
    else:
        gap = 16
    s.recv(1)
    while True:
        chunk = s.recv(4)
        if len(chunk) != 4:
            return
        if chunk == b'\x6c\x00\x00\x00':
            break
    s.recv(11)
    while True:
        length = s.recv(4)
        if len(length) != 4:
            return
        (length,) = unpack('!I', length)
        vhost = s.recv(length)
        if len(vhost) != length:
            return
        yield vhost.decode('ascii')
        step = s.recv(gap + 1)
        if len(step) != gap + 1:
            return


def parse_queues_recv(s):
    sock.settimeout(0.5)
    queues = b''
    try:
        while 1:
            data = sock.recv(65536)
            queues += data
    except timeout:
        pass
    queues = queues.split(b'\x52\x04\x6d')[1:]
    queues = [x.split(b'\x6a\x52\x06')[0][4:] for x in queues]
    return [(x.split(b'\x68\x02\x52\x05')[0].decode('ascii'),
             int.from_bytes(x.split(b'\x68\x02\x52\x05')[1][1:], byteorder='big'))
            for x in queues]


def get_erldp_port(target):
    psock = socket(AF_INET, SOCK_STREAM, 0)
    psock.connect((target, 4369))
    psock.sendall(pack('!HB6s', 7, 122, b'rabbit'))
    psock.recv(2)
    data = psock.recv(2)
    psock.close()
    (port,) = unpack('!H', data)
    return port


def get_erlang_cookie(target, path='/var/lib/rabbitmq/.erlang.cookie'):
    csock = socket(AF_INET, SOCK_STREAM, 0)
    csock.connect((target, 10050))
    key = ('system.run[cat %s]' % path).encode('ascii')
    csock.sendall(pack('<4sBQ', b'ZBXD', 1, len(key)) + key)
    data = csock.recv(1024)
    csock.close()
    length = unpack('<4sBQ', data[:13])[2]
    cookie = unpack('<%ds' % length, data[13:13 + length])[0]
    return cookie.decode('ascii')


def get_rabbit_version(target):
    csock = socket(AF_INET, SOCK_STREAM, 0)
    csock.connect((target, 10050))
    key = b'system.run[rpm -qa | grep rabbitmq-server | cut -d "-" -f 3]'
    csock.sendall(pack('<4sBQ', b'ZBXD', 1, len(key)) + key)
    data = csock.recv(1024)
    csock.close()
    length = unpack('<4sBQ', data[:13])[2]
    cookie = unpack('<%ds' % length, data[13:13 + length])[0]
    return cookie.decode('ascii')


if not args.port:
    args.port = get_erldp_port(args.target)


if not args.cookie:
    args.cookie = get_erlang_cookie(args.target)


name = rand_id()
sock = socket(AF_INET, SOCK_STREAM, 0)
assert sock
sock.connect((args.target, args.port))

sock.sendall(send_name(name))
data = sock.recv(5)
assert(data == b'\x00\x03\x73\x6f\x6b')
data = sock.recv(4096)
(length, tag, version, flags, challenge) = unpack('!HcHII', data[:13])
rabbitname = data[13:]
challenge = '%u' % challenge
sock.sendall(send_challenge_reply(args.cookie, challenge))
data = sock.recv(3)
if len(data) == 0:
    print('wrong cookie, auth unsuccessful')
    sys.exit(1)
else:
    assert (data == b'\x00\x11\x61')
    digest = sock.recv(16)
    assert (len(digest) == 16)


if args.mode == 'vhosts':
    data = pack('!7B%ss2B3s9I' % len(name), 131, 68, 2, 158, 0, 11, len(name), name,
                60, 3, b'rex', 0x68046113, 0x67520000, 0x00004c00, 0x00000001,
                0x52017200, 0x03520001, 0x000193d5, 0x75400007, 0x74c3c7c4)
    monitor_p = pack('!I', len(data)) + data

    reg_send_ticktime = pack('!3B34I', 0, 0, 0, 0x87834407, 0x86b19808, 0x0b05003c, 0x0c092467, 0x656e5f63,
                             0x616c6c0a, 0x0463616c, 0x6c940a6e, 0x65745f6b, 0x65726e65, 0x6c8f1067,
                             0x65745f6e, 0x65745f74, 0x69636b74, 0x696d6568, 0x04610667, 0x52000000,
                             0x004c0000, 0x00000352, 0x01520268, 0x03520368, 0x02675200, 0x0000004c,
                             0x00000000, 0x03720003, 0x52000300, 0x00cce5e6, 0xa4000132, 0x870ce868,
                             0x05520452, 0x0552066a, 0x67520000, 0x00003400, 0x00000003)

    demonitor_p = pack('!3B11I', 0, 0, 0, 0x2b834402, 0x16000b3c, 0x68046114, 0x67520000, 0x00004c00,
                       0x00000003, 0x52017200, 0x03520003, 0x0000cce5, 0xe6a40001, 0x32870ce8)

    reg_send_rabbit_vhosts = pack('!41I', 0x0000002b, 0x83440216, 0x000b3c68, 0x04611367, 0x52000000, 0x004c0000,
                                  0x00000352, 0x01720003, 0x52000300, 0x00cce7e6, 0xa4000132, 0x870ce800,
                                  0x00007183, 0x44070631, 0xa00b0b05, 0x3c0c0ad7, 0x0c726162, 0x6269745f,
                                  0x76686f73, 0x746b0869, 0x6e666f5f, 0x616c6c68, 0x04610667, 0x52000000,
                                  0x004c0000, 0x00000352, 0x01520268, 0x03520368, 0x02675200, 0x0000004c,
                                  0x00000000, 0x03720003, 0x52000300, 0x00cce7e6, 0xa4000132, 0x870ce868,
                                  0x05520452, 0x0552066a, 0x67520000, 0x00003400, 0x00000003)

    sock.sendall(monitor_p)
    sock.sendall(reg_send_ticktime)
    sock.recv(4096)
    sock.sendall(demonitor_p)
    sock.sendall(reg_send_rabbit_vhosts)
    for vhost in parse_vhost_recv(sock):
        print(vhost)

if args.mode == 'queues':
    rabbit_ver = get_rabbit_version(args.target)
    vhost = args.p.encode('ascii')
    if '3.7' in rabbit_ver:
        data = pack('!2BI', 131, 68, 0x029e000b) + \
               pack('!B%ss' % len(name), len(name), name) + \
               pack('!B10I', 60, 0x03726578, 0x68046113, 0x67520000, 0x00005300, 0x00000003,
                    0x52017200, 0x03520003, 0x00000e15, 0x942c0002, 0x34bee3c8)
        monitor_p = pack('!I', len(data)) + data
        sock.sendall(monitor_p)
        reg_send_ticktime = pack('!3B34I', 0, 0, 0, 0x87834407, 0x86d19808, 0x0b05003c, 0x96092467, 0x656e5f63,
                                 0x616c6c0a, 0x0463616c, 0x6c940a6e, 0x65745f6b, 0x65726e65, 0x6c8f1067,
                                 0x65745f6e, 0x65745f74, 0x69636b74, 0x696d6568, 0x04610667, 0x52000000,
                                 0x00530000, 0x00000352, 0x01520268, 0x03520368, 0x02675200, 0x00000053,
                                 0x00000000, 0x03720003, 0x52000300, 0x000e1594, 0x2c000234, 0xbee3c868,
                                 0x05520452, 0x0552066a, 0x67520000, 0x00003400, 0x00000003)
        sock.sendall(reg_send_ticktime)
        sock.recv(4096)
        demonitor_p = pack('!3B11I', 0, 0, 0, 0x2b834402, 0x16000b3c, 0x68046114, 0x67520000, 0x00005300,
                           0x00000003, 0x52017200, 0x03520003, 0x00000e15, 0x942c0002, 0x34bee3c8)
        sock.sendall(demonitor_p)
        data = pack('!33I', 0x83440906, 0x51b09b09, 0x0b053c96, 0x0a220f72, 0x61626269,
                    0x745f616d, 0x71717565, 0x7565ab0e, 0x656d6974, 0x5f696e66, 0x6f5f646f,
                    0x776e8c04, 0x6e616d65, 0x71086d65, 0x73736167, 0x65736804, 0x61066752,
                    0x00000000, 0x5d000000, 0x00035201, 0x52026803, 0x52036802, 0x67520000,
                    0x00005d00, 0x00000003, 0x72000352, 0x00030000, 0x0e32942c, 0x000234be,
                    0xe3c86805, 0x52045205, 0x52066c00, 0x0000046d) + \
               pack('!I%ss' % len(vhost), len(vhost), vhost) + \
               pack('!B13I', 108, 0x00000002, 0x52075208, 0x6a720003, 0x52000300, 0x000e2094,
                    0x2c000234, 0xbee3c867, 0x52000000, 0x004c0000, 0x0000036a, 0x67520000,
                    0x00003400, 0x00000003)
        reg_send_rabbit_queues = pack('!I', len(data)) + data
        data = pack('!3B7I', 131, 68, 10, 0x065130ab, 0x11000b05, 0x3c960a22, 0x770d656d, 0x69745f69,
                    0x6e666f5f, 0x616c6c6a) + \
               pack('!B%ss' % len(rabbitname), len(rabbitname), rabbitname) + \
               pack('!20I', 0x8c716804, 0x61066752, 0x00000000, 0x5e000000, 0x00035201,
                    0x52026803, 0x52036802, 0x67520000, 0x00005e00, 0x00000003, 0x72000352,
                    0x00030000, 0x0e39942c, 0x000234be, 0xe3c86805, 0x52045205, 0x52066c00,
                    0x0000056c, 0x00000001, 0x52076a6d) + \
               pack('!I%ss' % len(vhost), len(vhost), vhost) + \
               pack('!B13I', 108, 0x00000002, 0x52085209, 0x6a720003, 0x52000300, 0x000e2094,
                    0x2c000234, 0xbee3c867, 0x52000000, 0x004c0000, 0x0000036a, 0x67520000,
                    0x00003400, 0x00000003)
        reg_send_rabbit_queues += pack('!I', len(data)) + data
        sock.sendall(reg_send_rabbit_queues)
        queues = parse_queues_recv(sock)
        for x in queues:
            print(x)

    else:
        data = pack('!2BI', 131, 68, 0x02890052) + \
               pack('!B%ss' % len(name), len(name), name) + \
               pack('!B10I', 236, 0x03726578, 0x68046113, 0x67520000, 0x00000300, 0x00000002,
                    0x52017200, 0x03520002, 0x0000003b, 0x00000030, 0x00000000)
        monitor_p = pack('!I', len(data)) + data
        sock.sendall(monitor_p)
        reg_send_ticktime = pack('!3B34I', 0, 0, 0, 0x87834407, 0x81a0980f, 0x520500ec, 0xaf092467, 0x656e5f63,
                                 0x616c6c0a, 0x0463616c, 0x6c850a6e, 0x65745f6b, 0x65726e65, 0x6c2b1067,
                                 0x65745f6e, 0x65745f74, 0x69636b74, 0x696d6568, 0x04610667, 0x52000000,
                                 0x00030000, 0x00000252, 0x01520268, 0x03520368, 0x02675200, 0x00000003,
                                 0x00000000, 0x02720003, 0x52000200, 0x00003b00, 0x00003000, 0x00000068,
                                 0x05520452, 0x0552066a, 0x67520000, 0x00003000, 0x00000002)
        sock.sendall(reg_send_ticktime)
        sock.recv(4096)
        demonitor_p = pack('!3B11I', 0, 0, 0, 0x2b834402, 0x010052ec, 0x68046114, 0x67520000, 0x00000300,
                           0x00000002, 0x52017200, 0x03520002, 0x0000003b, 0x00000030, 0x00000000)
        sock.sendall(demonitor_p)
        monitor_p2 = pack('!3B11I', 0, 0, 0, 0x2b834402, 0x010052ec, 0x68046113, 0x67520000, 0x00000300,
                          0x00000002, 0x52017200, 0x03520002, 0x00000042, 0x00000030, 0x00000000)
        data = pack('!1B33I', 131, 0x440a0120, 0x80988900, 0x5205ecaf, 0x0ac20f72, 0x61626269,
                    0x745f616d, 0x71717565, 0x7565c308, 0x696e666f, 0x5f616c6c, 0x7d046e61,
                    0x6d656308, 0x6d657373, 0x61676573, 0x01047472, 0x75656804, 0x61066752,
                    0x00000000, 0x41000000, 0x00025201, 0x52026803, 0x52036802, 0x67520000,
                    0x00004100, 0x00000002, 0x72000352, 0x00020000, 0x00420000, 0x00300000,
                    0x00006805, 0x52045205, 0x52066c00, 0x0000066d) + \
               pack('!I%ss' % len(vhost), len(vhost), vhost) + \
               pack('!1B14I', 108, 0x00000002, 0x52075208, 0x6a520952, 0x09720003, 0x52000200,
                    0x00003e00, 0x00003000, 0x00000067, 0x52000000, 0x00030000, 0x0000026a,
                    0x67520000, 0x00003000, 0x00000002)
        reg_send_rabbit_queues = pack('!I', len(data)) + data

        sock.sendall(monitor_p2)
        sock.sendall(reg_send_rabbit_queues)
        queues = parse_queues_recv(sock)
        for x in queues:
            print(x)

sock.close()
