from Crypto.Util.number import getPrime, isPrime, GCD, bytes_to_long, long_to_bytes
from random import randrange
from hashlib import sha256

# Extended GCD
# Reference: https://www.geeksforgeeks.org/python-program-for-basic-and-extended-euclidean-algorithms-2/
def xgcd(a,b):
    if a == 0:
        return b, 0, 1
    gcd, x, y = xgcd(b%a, a)
    x, y = y - (b//a) * x, x
    return gcd, x, y

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
        while (GCD(g, self.N) != 1 or g == 1):
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
    def HashToPrime(content):
        '''
        Hash a content to Prime domain.
        The content must be encoded in bytes.
        '''
        def PrimeTest(p):
            return isPrime(p) and p > 2
        
        def H(_y):
            return bytes_to_long(sha256(_y).digest())
        
        y = H(content)
        while not PrimeTest(y):
            y = H(long_to_bytes(y))

        return y

    def add(self, content):
        '''
        Add an content to memberSet
        '''
        s = self.HashToPrime(content)
        self.memberSet.append(s)

    def MembershipProof(self, content):
        m = self.HashToPrime(content)
        if m not in self.memberSet: raise ValueError
        
        proof = self.g
        for s in self.memberSet:
            if s != m:
                proof = pow(proof, s, self.N)
        return proof

    @staticmethod
    def MembershipVerification(N, content, d, proof):
        m = RSA_Accumulator.HashToPrime(content)
        return pow(proof, m, N) == d

    def NonMembershipProof(self, content):
        
        m = self.HashToPrime(content)
        if m in self.memberSet: raise ValueError
        
        delta = 1
        for s in self.memberSet:
            delta *= s

        gcd, a, b = xgcd( m, delta )
        if a * m + b * delta != 1:
            raise ValueError
        
        return pow(self.g, a, self.N), b
    
    @staticmethod
    def NonMembershipVerification(N, content, d, proof, g):
        q, b = proof
        m = RSA_Accumulator.HashToPrime(content)
        return (pow(q, m, N) * pow(d, b, N)) % N == g

if __name__ == "__main__":
    
    A = RSA_Accumulator(1024)
    A.add(b"Hello!")
    A.add(b"Test!")
    
    d = A.Digest()
    N = A.N
    g = A.g
    proof = A.MembershipProof(b"Hello!")
    if RSA_Accumulator.MembershipVerification(N, b"Hello!", d, proof):
        print( "'Hello!' is in the set." )
    else:
        print( "The proof is wrong." )

    proof = A.NonMembershipProof(b"QAQ")
    if RSA_Accumulator.NonMembershipVerification(N, b"QAQ", d, proof, g):
        print( "'QAQ' is not in the set." )
    else:
        print( "The proof is wrong." )