from binascii import unhexlify


# The simplest of the encryption modes is the Electronic Codebook (ECB) mode (named after conventional physical codebooks).
# The message is divided into blocks, and each block is encrypted separately
# The disadvantage of this method is a lack of diffusion.
# Because ECB encrypts identical plaintext blocks into identical ciphertext blocks, 
# it does not hide data patterns well. 
# In some senses, it doesn't provide serious message confidentiality, and it is not recommended for use in cryptographic protocols at all.

# To Detect AES ECB line in file 8.txt you have to do the following :
# 1-Read all lines
# 2-iterate on each line and chunk it up to 16 chunks
# 3-check no of dupicates(repeation blocks) in each line
# 4-line with highest no of repeations is your encrypted AES line

def chunk_it_up(CT,chunk_size):
 chunks=[CT[i:i+chunk_size] for i in xrange(0,len(CT),chunk_size)]
 return chunks

def count_repeation(chunks):
 return len(chunks)-len(set(chunks))
 
def detect_aes_ecb():
 
  Repeation_list=[] # list will store no of no or repeation blocks in each line
  CTlines=open('8.txt').readlines()
  i=0 # counter for lines
  for line in CTlines :  
    i+=1
    line=unhexlify(line.strip())
    chunks=chunk_it_up(line,16)
    ecb_dict={'line_no':i,'Repeation_count':count_repeation(chunks)} # this will store each line no and no of corresponding repeations in this line chunks
    Repeation_list.append(ecb_dict)
  max_Repeation=sorted(Repeation_list,key=lambda x:x['Repeation_count'],reverse=True)[0]
  print "====[AES ECB Detected]====\n"+"\n".join("{}\t{}".format(k, v) for k, v in max_Repeation.items()) 
  
detect_aes_ecb()