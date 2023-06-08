import pefile
import re
from arc4 import ARC4
import base64

pe_handle = pefile.PE(r"filename")

def pe_traverse():
    for i in pe_handle.sections:
        if i.Name.startswith(b".rdata"):
            start_address = pe_handle.OPTIONAL_HEADER.ImageBase + (i.VirtualAddress)
            end_address = start_address + (i.Misc_VirtualSize)
            return (i.get_data())
 
def rc4_decryption(key,data):
    try:
        xx = base64.b64decode(data)
        cipher = ARC4(bytes(key))
        decrypted = cipher.decrypt(xx)
        return decrypted
    except:
        pass
    

rdata = pe_traverse()
rc4key = re.search(rb'\d{20}',rdata)
enc_data = (rdata[650:])
ss = re.finditer(rb'\b([A-Za-z0-9+/\==]){3,}',enc_data)

for i in ss:
    x = rc4_decryption(rc4key.group(),i.group())
    print(x)
