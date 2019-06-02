import base64
from Crypto.Cipher import AES #using pyCrypto is the best option here
#Decrypting AES ECB Mode using key 'YELLOW SUBMARINE'


def decrypt_aes(Msg,Key):
  
 CT=AES.new(Key,AES.MODE_ECB)
 pt=CT.decrypt(Msg)
 return pt
 
with open('7.txt') as f:
   f=base64.b64decode(f.read().strip())
   print decrypt_aes(f,"YELLOW SUBMARINE")
   
#or:   
#print decrypt_aes(base64.b64decode(open('7.txt').read().strip()),) # using one line ;)