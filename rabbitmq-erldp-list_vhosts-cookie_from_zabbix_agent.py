#!/usr/bin/python3
# -*- coding: utf-8 -*-
from struct import pack, unpack
from socket import socket, AF_INET, SOCK_STREAM
from hashlib import md5
from random import choice
from string import ascii_uppercase
import sys
import argparse


parser = argparse.ArgumentParser(description='Retrieve list of vhosts from RabbitMQ instance')

parser.add_argument('target', action='store', type=str, help='RabbitMQ node address or FQDN')
parser.add_argument('--cookie', type=str, default="", help='RabbitMQ Erlang cookie (/var/lib/rabbitmq/.erlang.cookie).')
parser.add_argument('--port', type=int, default=0, help='RabbitMQ Erlang TCP port')
parser.add_argument('--challenge', type=int, default=0, help='Set client challenge value')
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
    return pack('!HcI', len(response)+5, b'r', args.challenge) + response


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

demonitor_p1 = pack('!3B11I', 0, 0, 0, 0x2b834402, 0x16000b3c, 0x68046114, 0x67520000, 0x00004c00,
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
data = sock.recv(4096)
sock.sendall(demonitor_p1)
sock.sendall(reg_send_rabbit_vhosts)
print([x for x in parse_vhost_recv(sock)])
sock.close()
