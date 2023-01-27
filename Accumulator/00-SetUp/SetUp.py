from Crypto.Util.number import getPrime, GCD
from random import randrange
class RSA_Accumulator:
    def __init__(self, Nbits):
        self.Setup(Nbits)   # Run Trusted Setup
        self.Generate()     # Generate a generator
    
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
