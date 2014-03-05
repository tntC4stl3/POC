# coding: utf8
# MS09-001 SMB Could Allow Remote Code Execution (958687) - Remote Check
# Author: tntC4stl3
# http://tntcastle.net
# [+] test xp sp2, win 7 sp0
# Reference: http://openvas.komma-nix.de/nasl.php?oid=900233
#            http://hi.baidu.com/netcicala/item/620972bb2454f3a7ebba934a

import impacket
from impacket import smb
from impacket import nmb


def ms09001(remoteHost):
    r = smb.SMB(remote_name='*SMBSERVER', remote_host=remoteHost, sess_port = 445)
    r.login(user='', password='', domain='')

    # Get Tree ID and Process ID from the response packet
    uid = r.get_uid()
    if not uid:
        return 0

    path = r'\\%s\IPC$' % remoteHost
    tid = r.tree_connect_andx(path=path)

    # Construct Specially Crafted "\browser" Request
    smbPack = smb.NewSMBPacket()
    smbPack['Flags1'] = 0x08
    smbPack['Flags2'] = 0xc801
    smbPack['Tid'] = tid
    smbPack['Uid'] = uid
    smbPack['Pid'] = 0x4da2
    smbPack['Mid'] = 0x0b

    ntCreate = smb.SMBCommand(smb.SMB.SMB_COM_NT_CREATE_ANDX)
    ntCreate['Parameters'] = smb.SMBNtCreateAndX_Parameters()
    ntCreate['Data'] = smb.SMBNtCreateAndX_Data()
    ntCreate['Parameters']['FileNameLength'] = 16
    ntCreate['Parameters']['AndXOffset'] = 0x0000
    ntCreate['Parameters']['CreateFlags'] = 0 #16
    ntCreate['Parameters']['AccessMask'] = 0x2019f
    ntCreate['Parameters']['CreateOptions'] = 0 #0x400040
    ntCreate['Parameters']['ShareAccess'] = 3
    ntCreate['Parameters']['Impersonation'] = 2
    ntCreate['Parameters']['Disposition'] = 1
    ntCreate['Parameters']['SecurityFlags'] = 0

    # \browser
    ntCreate['Data'] = "\x00\x5c\x00\x62\x00\x72\x00\x6f\x00\x77\x00\x73\x00\x65\x00\x72\x00\x00\x00"
    smbPack.addCommand(ntCreate)
    r.sendSMB(smbPack)
    resp = r.recvSMB()

    if len(resp) < 103:
        return 0
    else:
        # Get FID from the response packet
        ntCreateResponse = smb.SMBCommand(resp['Data'][0])
        ntCreateParameters =smb.SMBNtCreateAndXResponse_Parameters(ntCreateResponse['Parameters'])
        fid = ntCreateParameters['Fid']

    # Construct Write AndX Request
    smbPack = smb.NewSMBPacket()
    smbPack['Flags1'] = 0x18
    smbPack['Flags2'] = 0xc803
    smbPack['Tid'] = tid
    smbPack['Uid'] = uid
    smbPack['Pid'] = 0x54dc
    smbPack['Mid'] = 0x0140
    data = """\x05\x00\x0b\x03\x10\x00\x00\x00
    \x48\x00\x00\x00\x00\x00\x00\x00
    \xb8\x10\xb8\x10\x00\x00\x00\x00
    \x01\x00\x00\x00\x00\x00\x01\x00
    \xc8\x4f\x32\x4b\x70\x16\xd3\x01
    \x12\x78\x5a\x47\xbf\x6e\xe1\x88
    \x03\x00\x00\x00\x04\x5d\x88\x8a
    \xeb\x1c\xc9\x11\x9f\xe8\x08\x00
    \x2b\x10\x48\x60\x02\x00\x00\x00"""

    writeAndX = smb.SMBCommand(smb.SMB.SMB_COM_WRITE_ANDX)
    smbPack.addCommand(writeAndX)

    writeAndX['Parameters'] = smb.SMBWriteAndX_Parameters()
    writeAndX['Parameters']['Fid'] = fid
    writeAndX['Parameters']['AndXOffset'] = 0
    writeAndX['Parameters']['Offset'] = 0
    writeAndX['Parameters']['WriteMode'] = 8
    writeAndX['Parameters']['Remaining'] = 72
    writeAndX['Parameters']['_reserved'] = 0xffffffff
    writeAndX['Parameters']['DataLength'] = 72
    writeAndX['Parameters']['DataOffset'] = 200 
    writeAndX['Parameters']['HighOffset'] = 0
    
    writeAndX['Data'] = data
    r.sendSMB(smbPack)
    resp = r.recvSMB()
    r.close(tid, fid)

    # Check the response and decide OS is vulnerable
    if (resp and ord(resp.rawData[4]) == 47 and ord(resp.rawData[5]) == 0  and
        ord(resp.rawData[6]) == 0 and ord(resp.rawData[7]) == 0 and ord(resp.rawData[8]) == 0):        
        return 1
    else:
        return 0

if __name__ == '__main__':
    remoteHost = '192.168.12.38'
    if ms09001(remoteHost):
        print '!!! VULN !!!'
    else:
        print 'patched or not effected'