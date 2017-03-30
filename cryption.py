import struct
import copy

class Cryption:
    keys2 = [ 0x00000000, 0x000000FF, 0x0000FFFF, 0x00FFFFFF ]
    first = True
    headerxor = 0xB43CC06E
    def __init__(self):
        self.keychain = [0]*0x20000
        self.generate_keychain(0x8F54C37B, 0, 0x4000)
        self.key = 0x6EC03CB4
        self.step = 0
        self.mul = 1

    def generate_keychain(self, key, pos, size):
        for i in range(pos, pos+size):
            ret4 = r32(key * 0x2F6B6F5)
            ret4 += 0x14698B7
            ret2 = ret4 = r32(ret4)
            ret4 = ret4 >> 0x10
            ret4 = r32(ret4 * 0x27F41C3)
            ret4 += 0x0B327BD
            ret4 = r32(ret4)
            ret4 = ret4 >> 0x10

            ret3 = r32(ret2 * 0x2F6B6F5)
            ret3 += 0x14698B7
            key = ret3 = r32(ret3)
            ret3 = ret3 >> 0x10
            ret3 = r32(ret3 * 0x27F41C3)
            ret3 += 0x0B327BD
            ret3 = r32(ret3)
            ret3 = ret3 >> 0x10
            ret3 = r32(ret3 << 0x10)

            ret4 = r32(ret4 | ret3)
            self.keychain[i*4:i*4+4] = list(struct.pack('I', ret4))
        

    def change_keychain(self, key, step):
        self.mul = 2
        self.step = step -1
        if self.step < 0:
            self.step = r32(self.step+0x4000)
        self.generate_keychain(key, 0x4000,0x4000)
        self.headerxor = struct.unpack('I', bytes(self.keychain[self.step*self.mul*4:self.step*self.mul*4+4]))[0]
        
        
    def encrypt(self,packet):
        pck = copy.copy(packet)+[0,0,0,0]
        size = len(pck)-4
        _4b = pck[:4]
        ppck = struct.unpack('I', bytes(_4b))[0] ^ 0x7AB38CF1
        ppck = r33(ppck)
        pck[:4] = list(struct.pack('I', ppck))

        token = ppck

        token = r33(token&0x3fff)
        token = r33(token*4)
        token = struct.unpack('I', bytes(self.keychain[token:token+4]))[0]

        t = int((size-4)/4)
        i = 4
        while t>0:
            t1 = struct.unpack('I', bytes(pck[i:i+4]))[0]
            t1 = r33(t1^token)
            pck[i:i+4] = list(struct.pack('I', t1))
            
            t1 = r33(t1 & 0x3fff)
            t1 = r33(t1*4)
            
            token = struct.unpack('I', bytes(self.keychain[t1:t1+4]))[0]
            t-=1
            i+=4
        token = r33(token & self.keys2[((size-4)&3)])
        _4b = pck[i:i+4]
        
        if len(_4b) < 4:
            _4b =  _4b+[0]* (4-len(_4b))
        _4b = struct.unpack('I', bytes(_4b))[0] ^token
        pck[i:i+4] = list(struct.pack('I', _4b))
        
        return pck[:size]

    
    def get_packet_size(self,packet, index):
        header = struct.unpack('I', bytes(packet[index:index+4]))[0]
        if self.first:
            return 0x0e
        header ^= self.headerxor
        header >>= 16
        return struct.unpack('i', struct.pack('I', header))[0]


    def decrypt(self, packet, index):
        header = self.get_packet_size(packet, index)
        size = len(packet)
        header <<=16
        header += 0xb7e2
        header = r32(header)
        if self.first:
            self.first = False
        ppck = packet[index:]
        token = struct.unpack('I', bytes(ppck[:4]))[0]
        token &= 0x3fff
        token*=self.mul
        token*=4
        token = r32(token)
        token = struct.unpack('I', bytes(self.keychain[token:token+4]))[0]
        ppck[:4] = list(struct.pack('I', header))
        i = 8
        t = int((size-8)/4)
        while t>0:
            t1 = struct.unpack('I', bytes(ppck[i:i+4]))[0]
            token ^=t1
            ppck[i:i+4] = list(struct.pack('I', token))

            t1 &= 0x3fff
            t1*=self.mul
            t1 *=4
            token = struct.unpack('I', bytes(self.keychain[t1:t1+4]))[0]
            i+=4
            t-=1
            

        token &= self.keys2[((size-8)&3)]
        _4b = ppck[i:i+4]
        if len(_4b) < 4:
            _4b =  _4b +[0] * (4-len(_4b))
        hd = struct.unpack('I', bytes(_4b))[0] ^ token
        ppck[i:i+4] = list(struct.pack('I', hd))
        ppck[4:8] = [0,0,0,0]
        self.step +=1
        self.step&= 0x3fff
        self.headerxor = struct.unpack('I', bytes(self.keychain[self.step*self.mul*4:self.step*self.mul*4+4]))[0]

        packet[index:] = ppck
        return packet[:size]
    
def r32(n):
    return n%4294967296

def r33(n):
    return n
