__version__ = "0.0.1"
__author__ = "SRE"

#Simple Cipher
import random

#Results
import re
from pprint import pprint

class cipherShift:
    
    def __init__(self):
        self.__valKey__ = r''
        self.__valPlaintext__ = r''
        self.__msgEncrypted__ = r''
        self.__msgEncryptedFinal__ = r''
        self.__msgDecrypted__ = r''
        self.__valChars__ = r'ABCDEFGHIJKLMNOPQRSTUVWXYZ'
        
    def genKeyRandom(self):
        tmpShuffled = sorted(self.__valChars__, key=lambda k: random.random())
        self.__valKey__ = dict(zip(self.__valChars__,tmpShuffled))
        return(self.__valKey__)

    def msgEncryptRandom(self,valPlaintext):
        self.__valPlaintext__ = valPlaintext
        return(''.join(self.__valKey__[l] for l in self.__valPlaintext__))

    def msgDecryptRandom(self,valCiphertext,valKey=None):
        if(valKey==None):
            valKey = self.__valKey__
        tmpFlipped = {v: k for k, v in valKey.items()}
        return(''.join(tmpFlipped[l] for l in valCiphertext))

    def genKeyShift(self,valShift):
        tmpShifted = []
        valLen = len(self.__valChars__)
        for i in self.__valChars__:
            tmpShifted.append(self.__valChars__[(self.__valChars__.index(i) + valShift) % valLen])
        self.__valKey__ = dict(zip(self.__valChars__,tmpShifted))
        return(self.__valKey__)
    
    def getTextReady(self,strPlaintext):
        self.__valPlaintext__ = strPlaintext
        strPlaintext = re.sub(r'[^\w\s]','',strPlaintext)
        strPlaintext = re.sub(r' ',r'',strPlaintext)
        strPlaintext = strPlaintext.upper()
        return(strPlaintext)

    def getSimpleCipherResults(self,strPlaintext,valChunkSize=5):
        self.__valPlaintext__ = strPlaintext
        strPlaintext = re.sub(r'[^\w\s]','',strPlaintext)
        strPlaintext = re.sub(r' ',r'',strPlaintext)
        strPlaintext = strPlaintext.upper()
        self.__msgEncrypted__ = self.msgEncryptRandom(strPlaintext)
        self.__msgDecrypted__ = self.msgDecryptRandom(self.__msgEncrypted__)
        tmpLen = valChunkSize-len(self.__msgEncrypted__) % valChunkSize
        tmpNulls = [random.choice(self.__valChars__) for _ in range(tmpLen)]
        self.__msgEncryptedFinal__ = self.__msgEncrypted__+''.join(tmpNulls)
        self.__msgEncryptedFinal__ = ' '.join([self.__msgEncryptedFinal__[i:i+valChunkSize] for i in range(0, len(self.__msgEncrypted__),valChunkSize)])
        return(self.__msgEncrypted__,self.__msgEncryptedFinal__,self.__valKey__)
    
    def getChars(self):
        return(self.__valChars__)
    
    def printContents(self):
        print('Key:')
        pprint(self.__valKey__)
        print(r'Plain Text: '+self.__valPlaintext__+"\n")
        print(r'Cipher Text: '+self.__msgEncryptedFinal__+"\n")
        print(r'Decrytped Text: '+self.__msgDecrypted__+"\n")
