import os #for securly generating random bytes
import random #for setting randomrange seed for os.urandom
from Crypto.Cipher import AES

def generate_rand_bytes(size_st,size_end=0):
  if size_end !=0:
    return os.urandom(random.randint(size_st,size_end))
  return os.urandom(size_st)
  
def chunk_it_up(CT,chunk_size):
 chunks=[CT[i:i+chunk_size] for i in xrange(0,len(CT),chunk_size)]
 return chunks
 
def pkcs7_padding(data,blocksize):

 pad_size=(blocksize-len(data))%blocksize#to keep padding_size within block boundries
 if pad_size==0: 
   pad_size=blocksize#set the pad_size the same as data length==blocksize
 padded_data=data+chr(pad_size)*pad_size #we use chr() instead which returns the hex representation of number
 return padded_data
 
def fixed_xor(block,key): #it's fixed xor between equal data types of same size (1st exercis)
 xored=bytearray([ord(b)^ord(k) for b,k in zip(block,key) ])
 return xored
 
#in any AES mode data must be padded to 16 bytes
def encrypt_aes_ecb(PT,key):
 encipher=AES.new(key,AES.MODE_ECB)
 return  encipher.encrypt(pkcs7_padding(PT,16))

 
def aes_cbc_enc(iv,PT,key): #using AES ECB
 CT=[] #empty list for storing encrypted blocks
 encipher=AES.new(key,AES.MODE_ECB) #initializing our cipher AES cipher mode
 chunks=chunk_it_up(PT,16) #chunk the plain text into chunks 16 bytes each
 xored=fixed_xor(chunks[0],iv) #then xor the first block with IV
 enc_block=encipher.encrypt(xored) #encrypt the xored string with input key
 CT.append(enc_block) #adding enc block to out CT list
 del chunks[0] #deleting the first block , thus interate over other chunks freely
 for chunk in chunks: #now for the all chunks other than first one
   xored=fixed_xor(enc_block,chunk) #xor each chunk with prev enc_block
   enc_block=encipher.encrypt(xored) #then encrypt it again with same input key
   CT.append(enc_block) # and finally add enc block to our CT list
 return ''.join(CT)

def encrypt_aes_random(PT):
 #this fn randomly generate Key,IV and some randome generate bytes and randomly select the AES Mode
 rand_key= generate_rand_bytes(16)
 rand_iv= generate_rand_bytes(16)
 pre_rand=generate_rand_bytes(5,10)
 post_rand=generate_rand_bytes(5,10)
 PT=pre_rand+PT+post_rand
 mode=random.randint(0,1)
 if mode==0: #go for CBC mode
    print "using CBC Mode";return aes_cbc_enc(rand_iv,pkcs7_padding(PT,16),rand_key)
 else: #go for ECB mode
    print "using ECB Mode";return encrypt_aes_ecb(PT,rand_key)

def detect_aes_mode(CT):
  bytes_chunked=chunk_it_up(CT,16)
  new_list=set(bytes_chunked)
  if(len(bytes_chunked)-len(new_list) >0):
     print "this text was encrypted using AES ECB Mode !!"
  else :
     print "this text was encrypted using AES CBC Mode !!"

	 
'''
|rand bits        |      choosen plaintext            |rand bits        |
-------------------------------------------------------------------------
|<-5 to 10 bytes->|<-    we can decide the size     ->|<-5 to 10 bytes->|
-------------------------------------------------------------------------
|<- 16 bytes       ->|<- 16 bytes ->|<- 16 bytes ->|<-   16 bytes     ->|
-------------------------------------------------------------------------
                  |??|                             |??|
'''

#to detect ECB we need at least two identical blocks (16 bytes each)
#the first random block range is between (5,10) [whole block is 16] , our best case would be (16-10) 6 and in worstcase (16-5) 11
#we take worstcase in pur consideration [the first block generator generates only 5 bytes and thus we still have 11 more bytes to complete the first block(16 bytes)]
#then our 2 indential blocks (16+16=32) so the total identical bytes needed = 32+11=43 identical bytes
#so we generate 43 identical bytes thus filling our two blocks and filling shortage in the firstblock(if happened)
pt=chr(random.randint(0,256))*43  #using random.randint to generate random number in range of noraml byte and then uing chr fn to convert the generated no into byte representation  
random_enc_shit=encrypt_aes_random(pt)
detect_aes_mode(random_enc_shit)