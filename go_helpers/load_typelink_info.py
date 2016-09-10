#!/usr/bin/env python

import re
import sys
import base64
import r2pipe

def loadTypeLinkTab(start, end):
    typelink_tab = []
    off = start
    while off < end:
        typelink_tab += [ int(r2.cmd("pf p4 @ "+ hex(off) + "~[1]"), 16) ]
        off += 8
    return typelink_tab
    

r2 = r2pipe.open()

typelink_start = int(r2.cmd("iS~typelink[3]"), 16)
typelink_sz = int(r2.cmd("iS~typelink[7]"))
typelink_end = typelink_start + typelink_sz


first = int(r2.cmd("pf p4 @ " + hex(typelink_start) + "~[1]"),16)
last = int(r2.cmd("pf p4 @ " + hex(typelink_end-8) + "~[1]"),16)

print "[+] Loading disassemble..."
disasm = r2.cmdj("pDj $SS@$S")

print "[+] Loading .typelink table..."
typelink_tab = loadTypeLinkTab(typelink_start, typelink_end)

print "[+] Looking for types..."
count = 0
if disasm:
    for i, instr in enumerate(disasm):
        if "opcode" in instr:
            res = re.match(".*, \[rip \+ (0x[0-9a-f]+)\]", str(instr["opcode"])) 
            if res:
                ref = int(res.group(1), 16)
                offset_cmt = instr["offset"]
                rip = disasm[i+1]["offset"]
                s = ref + rip
            
                if s in typelink_tab:
                    off = int(r2.cmd("pf p4 @ "+hex(s + 40)+"~[1]"), 16)
                    off2 = int(r2.cmd("pf p4 @"+hex(off)+"~[1]"), 16)
                    sz = r2.cmd("pf p2 @"+hex(off+8)+"~[1]")
                    sym = r2.cmd("ps "+sz+" @ "+hex(off2))
                    cmd = "CCu base64:" + base64.b64encode(sym) + " @ " + str(offset_cmt)
                    r2.cmd(cmd)
                    count += 1
print "[+] Loaded %s type references!" % count
r2.quit()
