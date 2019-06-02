import base64
from Crypto.Cipher import AES
import string
from os import urandom

def encrypt_aes_ecb(PT,k=0): #k var is placed for debugging , seeing plaintext just before enc
 key='YELLOW SUBMARINE'
 random_prefix=urandom(50)
 secret=base64.b64decode('Um9sbGluJyBpbiBteSA1LjAKV2l0aCBteSByYWctdG9wIGRvd24gc28gbXkgaGFpciBjYW4gYmxvdwpUaGUgZ2lybGllcyBvbiBzdGFuZGJ5IHdhdmluZyBqdXN0IHRvIHNheSBoaQpEaWQgeW91IHN0b3A/IE5vLCBJIGp1c3QgZHJvdmUgYnkK')
 plain=random_prefix+PT+secret;
 if k==1: return plain
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

def ecb_byte_at_time(blocksize,secret_len,prefix_padding,perfix_span_blocks):
 charset=string.printable #setup charset for bruteforce
 secret='' #var for storng decrypted secret chars
 prefix_length=perfix_span_blocks*blocksize #worst case prefix length (block aligned)
 secret_len=secret_len-prefix_length #beacuse secret_len is calculated with dummy text subtracted from it but still the random prefix and + random padding must be substacted ,so we substract worstcase prefix length (block aligned)
 secret_len_rounded=((secret_len / blocksize) +1) *blocksize #roundup (scale) the secret_len to a multiple of blocksize
 #print secret_len_rounded
 for i in xrange(secret_len_rounded-1,0,-1): #now itertae backwords over the secret_len_rounded-1 ('-1' so that we leave space for our secret text for bruteforcing (e.g if block size is 3) AAa,AAb,AAc and so on)
   #prefix_padding is added to no of our dummy text as to padd the random_prefix so our payload could start using a new block
   #this time we slice from pefix_span_blocks bytes as starting point,[in ch12 we slice from 0 beause there was no random prefix before our payload]
   reference=encrypt_aes_ecb('A'*(i+prefix_padding))[perfix_span_blocks*blocksize:secret_len_rounded+prefix_length]#;print reference;exit(0)  #setting up our reference (changes every round in loop according to 'i') and slicing output to our prev scaled secret len
   for char in charset:
      test=encrypt_aes_ecb('A'*(i+prefix_padding)+secret+char)[perfix_span_blocks*blocksize:secret_len_rounded+prefix_length]#;exit(0) #now enc dummy text + secret found char + char being bruteforced
      if (test==reference): #once test matches the reference
           secret+=char #then it's defently our secret char
           print "[+]Found secret char is "+char
           break      #now break the loop and setup a new-reference for next round and so on..
	
 return secret #return stored secret string


def random_prefix_padding(blocksize):
    prefix_length = 0
    prefix_padding=0
    for i in range(blocksize*2, blocksize*3): #begining is 32 beacuse we need to feed to aes_ecb at least two identical blocks ,
      t = b'A'*i                              #fill up to 3 identical blocks
      enc = encrypt_aes_ecb(t)
      num_blocks = len(enc)/blocksize#;print num_blocks  #calculating no of blocks in CT
      for j in range(1,num_blocks):           #now seaching for identical blocks within no of blocks counted previuosly
        if enc[j*blocksize:(j+1)*blocksize] == enc[(j+1)*blocksize:(j+2)*blocksize]: #compare next two blocks, however we still don't know the random prefix size in the first block so we begin from ideal case assuming that random prefix is 16 bytes we begin to compare second and third block and check if they are similar , that would mean that random prefix is 16 bytes filling 1st block if it's not ,then keep increasing no of blocks to check 3,4 
          # why blocksize*3 ?? beacuse we always consider 3 blocks in our above equation j*blocksize,(j+1)*blocksize,(j+2)*blocksize , and relation between j (no of blocks in CT) and random_prefix length is direclty proportional so it will always be the same result , it will always give the result of **rounded** <=blocksize(16 in ouR case) random_prefix bytes , e.g if random_prefix=20, this equation result will be 4 (rounded random prefix bytes , since 16 already filled first block)
          prefix_length = blocksize*3 - i #**ROUNDED** the prefix length = 48(number of bytes in 3 blocks ) - i (no of filling bytes at least filling two blocks 32 bytes)
          prefix_span_blocks = j # how many blocks does the prefix span occupy, j is the last boundry of the random prefix and it's also considered the starting point of our identical buffer
          prefix_padding=abs(blocksize-prefix_length) #calculate the padding of prefix blocksize-prefixlength , using abs is mandatory in case prefix length is greater than blocksize
          prefix_length_worstcase=prefix_span_blocks *blocksize
          #print prefix_length,prefix_padding,i
          return prefix_padding,prefix_span_blocks#,prefix_length_worstcase,
          break
      if prefix_padding: break # break out of the 2nd loop
	  
#print random_prefix_padding()
blocksize=getting_block_size()
secret_len=getting_secret_size()
prefix_padding,perfix_span_blocks=random_prefix_padding(blocksize)
print ecb_byte_at_time(blocksize,secret_len,prefix_padding,perfix_span_blocks)

 
