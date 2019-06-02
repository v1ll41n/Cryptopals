import base64
from Crypto.Cipher import AES
import string

#Crypopals Challenge #12 : REAL Life Crypto Attack
'''
if we have an AES ecb fn that encrypts our input and secretly adding to it some kind of secret plaintext just before encryption
we can still **Approxemetly** determine secret plaintext length and decrypt it byte-by-byte
Here are the steps for doing that:
1-determine Encryption Block size:
throught using dummy interative input A,AA,AAA and feed it to aes enc function
begin with single char e.g 'A' and note down CT length ,now loop over enc fn with dummy text length increasing A,AAA,AAAA,AAAAA and notice the change in 
CT length (let padding do it's work ;) ) so when CT length change ,subtract it from old CT length , the diff between old len  and current len is the block size :D

2-Determine secret plaintext length approx ****Approxemetly***:
why i said ****Approxemetly***? well, because in fact we are almost calculating **how many bytes in which the secret text will be included (with padding)*** not the secret real size
this is done the same way we calculated blocksize , the real diff here is that we calculate the difference between the iterative dummy text (AAAAA) and the length of the corresponding new CT length once CT length is changed
for example if we have dummy text of length 1 'A' and secret of length 14 "IAMHUNGRYNOW!!" now when encrypting this with blocksize 16
'AIAMHUNGRYNOW!!' (15 chars) it will be encrypted and results in (16 bytes)
now if the secret length is >14 (** padding takes place even if the pt size = block size) e.g "IAMHUNGRYNOW!!!!"
the pt encrypted will be 'AIAMHUNGRYNOW!!!!' (17 char) will result of 32 CT output (16 for the first block 'AIAMHUNGRYNOW!!!' and 16 for the second block '!+padding')
now subtract 32-len(dummy_text) =32-1=30 (in reality secret size is 17 chars :D), now you see clearly what i mean by ****Approxemetly***

3-setup your charset for bruteforcing (you can use string module)
4-scale up (round) your **appx** secret size to your prev determined blocksize
4-take a refernce of enc string with length sclaed_secret_len-1 so that we can bruteforce the first char of our secret
5-iterate over the prev prepared charset and compare the CT to the reference if they are equal then you have found the correct char
6-loop over sclaed_secret_len till reaching 1 and voila you found the secret pt

'''

def encrypt_aes_ecb(PT):
 key='YELLOW SUBMARINE'
 secret=base64.b64decode('Um9sbGluJyBpbiBteSA1LjAKV2l0aCBteSByYWctdG9wIGRvd24gc28gbXkgaGFpciBjYW4gYmxvdwpUaGUgZ2lybGllcyBvbiBzdGFuZGJ5IHdhdmluZyBqdXN0IHRvIHNheSBoaQpEaWQgeW91IHN0b3A/IE5vLCBJIGp1c3QgZHJvdmUgYnkK')
 plain=PT+secret
 encipher=AES.new(key,AES.MODE_ECB)
 return  encipher.encrypt(pkcs7_padding(plain,16))
 
 
def pkcs7_padding(data,blocksize):

 pad_size=(blocksize-len(data))%blocksize
 if pad_size==0: 
   pad_size=blocksize
 padded_data=data+chr(pad_size)*pad_size
 return padded_data

 
def getting_secret_size():
  reference=len(encrypt_aes_ecb('A'))
  i=2
  while True:
    new=len(encrypt_aes_ecb('A'*i))
    diff=new-reference
    if (diff!=0):    #once the length of CT is changed (new block is added)
	    return new-i #return approximatley no of bytes in which secret text is located +padding -length of dummy text*
    i+=1 
 
def getting_block_size():
  reference=len(encrypt_aes_ecb('A'))
  i=2
  while True:
    new=len(encrypt_aes_ecb('A'*i))
    diff=new-reference 
    if (diff!=0): #once the length of CT is changed (new block is added)
	    return diff #return the diff in CT length (block size)
    i+=1

def ecb_byte_at_time(blocksize,secret_len):
 charset=string.printable #setup charset for bruteforce
 secret='' #var for storng decrypted secret chars
 secret_len_rounded=((secret_len / blocksize) +1) *blocksize #roundup (scale) the secret_len to a multiple of blocksize
 #print secret_len_rounded
 for i in xrange(secret_len_rounded-1,0,-1): #now itertae backwords over the secret_len_rounded-1 ('-1' so that we leave space for our secret text for bruteforcing (e.g if block size is 3) AAa,AAb,AAc and so on)
   reference=encrypt_aes_ecb('A'*i)[:secret_len_rounded] #setting up our reference (changes every round in loop according to 'i') and slicing output to our prev scaled secret len
   for char in charset:
      test=encrypt_aes_ecb('A'*i+secret+char)[:secret_len_rounded] #now enc dummy text + secret found char + char being bruteforced
      if (test==reference): #once test matches the reference
           secret+=char #then it's defently our secret char
           print "[+]Found secret char is "+char
           break      #now break the loop and setup a new-reference for next round and so on..
	
 return secret #return stored secret string

blocksize=getting_block_size()
secret_len=getting_secret_size()
print ecb_byte_at_time(blocksize,secret_len)
#print len(encrypt_aes_ecb(''))

 
