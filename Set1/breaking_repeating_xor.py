from binascii import *
import base64
import clipboard
'''
Breaking Repeating Key Xor using Friedman Test (hamming distance between bytes on bitwsie)

'''


def hamming_dist(msg1,msg2):
 dist=0
 xored=[bin(ord(i)^ord(j)) for i,j in zip(msg1,msg2)] #list contains decimal values of two xored msgs
 #print xored 
 dist+=sum([1 for bits in xored for bit in bits if bit=='1']) #nested for loop in list comprehension
 return dist
 
def chunk_it_up(CT,chunk_size):
 chunked=[CT[i:i+chunk_size] for i in xrange(0,len(CT),chunk_size)]
 return chunked

def getting_key_size(CT):
  chunks_avg=[] #for storing avg hamming distances among each key
  possible_key_sizes=[] #for storing possible key Sizes
  for key_size in range(2,40): #range from 2,4 step=1
    chunks=chunk_it_up(CT,key_size)
    chunks_dist=[]#storing chunks hamming dist for same key
    for i in range(len(CT)/(key_size*2)):#while True:
      chunks_dist.append(hamming_dist(chunks[0],chunks[1])/key_size) #noramlizing hammin distance by dividing by Key_size
      if(i==len(CT)/(key_size*2)-1): break;
      del chunks[0]
      del chunks[1]
    res={'key':key_size,'avg_dist':float(sum(chunks_dist))/len(chunks_dist)} #using float() in adding hamming dist yeilds in more accurate results
    chunks_avg.append(res)
  chunks_avg=sorted(chunks_avg,key=lambda x:x['avg_dist'])
  possible_key_sizes=[key['key'] for key in chunks_avg[:3] ] #take the first 3 key_sizes whit least small hamming_distance
  return possible_key_sizes
  
def transpose_chars(CT,key_size,i):
   block=[CT[char] for char in xrange(i,len(CT),key_size) ]
   return block
     
def get_english_score(input_bytes):
    character_frequencies = {
        'a': .08167, 'b': .01492, 'c': .02782, 'd': .04253,
        'e': .12702, 'f': .02228, 'g': .02015, 'h': .06094,
        'i': .06094, 'j': .00153, 'k': .00772, 'l': .04025,
        'm': .02406, 'n': .06749, 'o': .07507, 'p': .01929,
        'q': .00095, 'r': .05987, 's': .06327, 't': .09056,
        'u': .02758, 'v': .00978, 'w': .02360, 'x': .00150,
        'y': .01974, 'z': .00074, ' ': .13000
    }
    return sum([character_frequencies.get(chr(byte), 0) for byte in input_bytes.lower()])

def single_xor(block,key):
  xored=bytearray([key^ord(b) for b in block])
  return xored
  
def repeating_xor(Message,key):
  diff=len(Message)-len(key)
  if(diff>0):
    key=key*diff #repeating key (n) times where n is the diff between message length and key length
    res=bytearray([ord(i)^ord(j) for i,j in zip(key,Message)])
    return res 
	
def xor_brute(block):

   scorelist=[]
   for i in xrange(256):
       plain=single_xor(block,i)
       pscore=get_english_score(plain)
       data={ 'key':i,'score':pscore,'deciphered':plain }
       scorelist.append(data)
   possible_plaintext=sorted(scorelist,key=lambda x: x['score'],reverse=True)[0]
   return possible_plaintext['key']

def breaking_rxor(CT):
   key=''
   plaintext=''
   possible_key_sizes=getting_key_size(CT)
   for possible_key in possible_key_sizes:
       for i in xrange(possible_key):
         block=''.join(transpose_chars(CT,possible_key,i))
         key+=chr(xor_brute(block))
       plaintext=repeating_xor(CT,key)
       print "====[Using Key "+`possible_key`+"]====\nXoring key ="+key+"\nand plain text="+plaintext+"\n";break#remove the break if you are not satisfied with rsult
    
     
breaking_rxor(base64.b64decode(open('6.txt').read().strip()))