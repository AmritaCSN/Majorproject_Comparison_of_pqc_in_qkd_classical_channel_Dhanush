from kyber import Kyber512
import os
import difflib

m=os.urandom(1)
pk,sk=Kyber512.keygen()
key,output = Kyber512.enc(pk,m)
byte_data = bytearray(pk)
byte_data[-1] = 0x11 
    # Convert back to bytes
new_data = bytes(byte_data)
op_cipher,op_test = Kyber512.enc(new_data, m)
print('sec key',sk)
dec=Kyber512.dec(key,sk)
byte_data1 = bytearray(key)
byte_data1[-2] = 0x12 
byte_data1[-1] = 0x10 
    # Convert back to bytes
new_data1 = bytes(byte_data1)
print('sec key after',new_data1)
dec_out = Kyber512.dec(new_data1,sk)
    
t = 0
print(len(dec),len(dec_out))
for i in range(len(dec)):
        if dec[i] == dec_out[i]:
            t=t+1
percnt = (t/len(dec))*100
ratio = difflib.SequenceMatcher(None, key, op_cipher).ratio()

# Print the similarity ratio as a percentage
print(f"The similarity between the two byte arrays is {ratio/len(key):.5f}%")
print("Key sensitivity analysis of encryption-similarity in percentage",percnt)
print('key is',output)
print('shared key is',dec)
print('shared key is',dec_out)
