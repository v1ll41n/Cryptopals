from Crypto.Cipher import AES
import base64
#**Note** data (encoded/decoded) must be padded before encoding/decoding 

#to encrypt in AES 128-bit in CBC Mode : manually using ***ECB mode***
#****the key must be 16 bytes and IV must be 16 bytes and data must be **padded** to 16 bytes*****
#1-chunk the plain text into 16 bytes each
#2-xor first chunk with iv and then encrypt it with AES ECB mode with given key
#3-now for the next chunk it will be xored with prev ciphertext(aes-encrypted) and then encypted with same key

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

def pkcs7_padding(data,blocksize):

 pad_size=(blocksize-len(data))%blocksize#to keep padding_size within block boundries
 if pad_size==0: 
   pad_size=blocksize#set the pad_size the same as data length==blocksize
 padded_data=data+chr(pad_size)*pad_size #we use chr() instead which returns the hex representation of number
 return padded_data
 
def chunk_it_up(CT,blocksize):
 block=[CT[i:i+blocksize] for i in xrange(0,len(CT),blocksize)]
 return block
#print chunk_it_up("hey this is me",2) 

def fixed_xor(block,key): #it's fixed xor between equal data types of same size (1st exercis)
 xored=bytearray([ord(b)^ord(k) for b,k in zip(block,key) ])
 return xored
 
#to decrypt in AES 128-bit in CBC Mode : manually using ***ECB mode***
#****the key must be 16 bytes and IV must be 16 bytes and data must be **padded** to 16 bytes*****
#same steps as encryption are applied in reverse
#1-chunk the cipher text into 16 bytes each
#2-decrypt first chunk with the given key AES ECB mode and then xor it with iv to get first block in plaintext
#3-now for the next chunk it will be decrypted with same key and then xored with prev **cipher block** to get current block in plaintext
 
def aes_cbc_dec(iv,CT,key): #using AES ECB
 PT=[] #empty list for storing plaintexts blocks
 decipher=AES.new(key,AES.MODE_ECB) #initializing our cipher AES cipher mode
 chunks=chunk_it_up(CT,16) #chunk the cipher text into chunks 16 bytes each
 dec_block=decipher.decrypt(chunks[0]) #decrypt the first block with input key
 xored=fixed_xor(dec_block,iv) #then xor the first block with IV
 PT.append(xored) #adding xored(plain) block to our PT list
 prev_CT=chunks[0] #storing first chunk to be used as prev Cipher block sor xoring with next chunks
 del chunks[0] #deleting the first block , thus interate over other chunks freely
 for chunk in chunks: #now for the all chunks other than first one
   dec_block=decipher.decrypt(chunk);#print xored;print dec_block;break #decrypt each chunk it with same input key
   xored=fixed_xor(prev_CT,dec_block) #then xor each dec_block with prev **cipher text**
   prev_CT=chunk #overwriting prev_CT with current chunks for the next iteration   
   PT.append(xored) # and finally add decrypted block to our CT list
#to clean string before returning plaintext 
#we use The map() function that applies a given function to each item of an iterable (list, tuple etc.) 
#and returns a list of the results.
#we could use return ''.join(str(j) for j in PT) OR :
 return  ''.join(map(str, PT)) #here we are returning only values which has ascii str values thus truncating non-ascii chars ;)
 
key="YELLOW SUBMARINE"
iv=chr(0)*16
#print aes_cbc_enc(iv,pkcs7_padding("my password is 952145",16),key)
#print aes_cbc_dec(iv,aes_cbc_enc(iv,pkcs7_padding("my password is kokoki",16),key),key)
padded_data=pkcs7_padding(base64.b64decode(open('10.txt','r').read().strip()),16)
print aes_cbc_dec(iv,padded_data,key)