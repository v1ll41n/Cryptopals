from Crypto.Cipher import AES
from os import urandom
#CryptoPals CH16 Set2 last challenge
#CBC Bit Flipping
'''
in this attack we exploit the fact that a 1-bit error in a ciphertext block:
1- Completely scrambles the block the error occurs in
2- ****Produces the identical 1-bit error(/edit) in the next ciphertext block.
this 1-bit error is what we will use to conduct our attacks
here in this challenge we have AES CBC functions that filters out ';' and '=' from input plaintexts
our goal is to insert normal text e.g ":" and "@" and then using bit flipping error to convert these characters to our target chars
for this challenge we wil use 2 blocks as an input ,the first block doesn't matter (will act as helper for performing bit flipping in th next block thus changing normal chars to our target chars)
i will list the equations i used to understand this process (mathmatical prove)
consider our target block plain text is PT2 and dummy block cipher text is C1 and PT'2 is our-bits flipped-plain text resulted from decryption are (new PT2)
PT2=D(CT2,K) ^ CT1  # this is normal cbc operation
zero=D(CT1,K) ^ CT1 ^ PT2 #xoring two equals values = zero
PT'2 =D(CT1,K) ^ CT1 ^ PT2 ^ PT'2
okay we can control [CT1(before dec process),PT2(our input before bit flipping),Tb(PT2 bit flipped values)]
therefore : let call CT'1=CT1 ^ PT2 ^ Tb [altered CT1]
PT' = D(CT1,K) ^  CT'1
Note than (D(CT1,K)) is already done in dec process (we can't control it)


'''
def aes_cbc_enc(iv,PT,key): #using AES ECB
 CT=[] #empty list for storing encrypted blocks
 PT=PT.replace(";",'') #filterout ';'
 PT=PT.replace("=",'') #filterout '='
 #prefix before payload" **Note that here we MUST know prefix length (can't be random)
 #because we can't determine prefix length in case of random prefix like we did in case of ECB becuase in ECB 
 #we used the property of ECB of idetical PT produce identical CT to determine random prefix length , we can't do that here in CBC
 PT_prefix="comment1=cooking%20MCs;userdata=" #note that the prefix length is 32 bytes (2 aligned blocks)
 PT_postfix=";comment2=%20like%20a%20pound%20of%20bacon" #prefix after payload"
 PT=pkcs7_padding(PT_prefix+PT+PT_postfix,16)
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
 plain= ''.join(map(str, PT)) #here we are returning only values which has ascii str values thus truncating non-ascii chars ;)
 if ";admin=true;" in plain: print "PWNNNNNNNEEEEED YAAAY!!" #a check just to know wether we broke the crypto or not 
 else : print "Filtered :("
 return plain
 
payload1=";admin=true;" #our normal payload which is rejected/filtered by enc fn
payload11=":admin@true;" #our modified payload with target bytes replaced temporary
payload2='0'*20+payload11 # now we setup our payload we need two blocks (1-> dumy block , 2-> target block contains our payload) = 32 bytes
b1=(32+5)-1 #Here we determine the offset of target bits in **Dummy block** that will flip the bits with same offset in **Target Block**
b2=(32+11)-1 #32 is length of prefix ,'-1' as we deal with 0-indexed bytearray :D
random_key=urandom(16) #random key 
random_IV=urandom(16)  #random iv
enc=bytearray(aes_cbc_enc(random_IV,payload2,random_key))
enc[b1]=enc[b1]^ord(';')^ord(':')#we have already discussed this flipping process
enc[b2]=enc[b2]^ord('@')^ord('=')
print aes_cbc_dec(random_IV,bytes(enc),random_key) #finally decryption
