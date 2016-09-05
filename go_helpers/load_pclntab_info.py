#!/usr/bin/env python

import re
import sys
import base64
import r2pipe

r2 = r2pipe.open()
bits = int(r2.cmd("i~bits[1]"))

ptr_sz = 8 if bits == 64 else 4

base = int(r2.cmd("iS~.gopclntab[3]"), 16)
cur = base + ptr_sz # skip header
size = int(r2.cmd("pf p4~[1] @ " + str(cur) + "~[1]"), 16)
cur += ptr_sz
end = cur + (size * ptr_sz * 2)

print "[+] Reading .gopclntab section..."
count = 0
while cur < end:
    offset = int(r2.cmd("pf p4 @ " + str(cur + ptr_sz) + "~[1]"), 16)
    cur += ptr_sz * 2

    faddr = int(r2.cmd("pf p4 @ " + str(base + offset) + "~[1]"), 16)
    noffset = int(r2.cmd("pf p4 @ " + str(base + offset + ptr_sz) + "~[1]"), 16)
    name = r2.cmd("ps @ " + str(base + noffset))
    clean_name = re.sub("[^a-zA-Z0-9\n\.]", "_", name)
    r2.cmd("af @ " + hex(faddr))
    r2.cmd("afn " + clean_name +" @ " + hex(faddr))
    r2.cmd("CCu base64:" + base64.b64encode(name) +" @ " + hex(faddr))
    count +=1
    print "\r[+] Found %d functions" % count,

r2.quit()
