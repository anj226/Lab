from Crypto.Util.number import getPrime, isPrime, GCD, bytes_to_long, long_to_bytes
from random import randrange
from hashlib import sha256

class RSA_Accumulator:
    def __init__(self, Nbits):
        self.Setup(Nbits)       # Run Trusted Setup to get the N of a RSA group
        self.Generate()         # Generate a generator g for the RSA group
        self.memberSet = []     # The memberSet S

    def Setup(self, Nbits):
        '''
        RSA Accumulator needs trusted setup from third-party.
        The fator of N should not be known.
        '''
        self.N = getPrime((Nbits+1)//2) * getPrime((Nbits+1)//2)
    
    def Generate(self):
        '''
        Generate a generator g in Z_N^*.
        '''
        g = randrange(1,self.N)
        while (GCD(g, self.N) != 1 and g != 1):
            g = randrange(1,self.N)        
        self.g = g

    def Digest(self):
        '''
        Digest all the contents in memberSet.
        '''
        self.d = self.g
        for s in self.memberSet:
            self.d = pow(self.d, s, self.N)
        
        return self.d

    @staticmethod
    def PrimeTest(p):
        return isPrime(p) and p > 2

    def HashToPrime(self, content):
        '''
        Hash a content to Prime domain.
        The content must be encoded in bytes.
        '''
        def H(_y):
            return bytes_to_long(sha256(_y).digest())
        
        y = H(content)
        while not self.PrimeTest(y):
            y = H(long_to_bytes(y))

        return y

    def add(self, content):
        '''
        Add an content to memberSet
        '''
        s = self.HashToPrime(content)
        self.memberSet.append(s)


if __name__ == "__main__":
    
    A = RSA_Accumulator(1024)
    A.add(b"Hello!")
    A.add(b"Test!")
    print(A.Digest())
    