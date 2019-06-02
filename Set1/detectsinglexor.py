from binascii import *

def get_english_score(input_bytes):
    """Compares each input byte to a character frequency 
    chart and returns the score of a message based on the
    relative frequency the characters occur in the English
    language
    """
    # From https://en.wikipedia.org/wiki/Letter_frequency
    # with the exception of ' ', which I estimated.
    character_frequencies = {
        'a': .08167, 'b': .01492, 'c': .02782, 'd': .04253,
        'e': .12702, 'f': .02228, 'g': .02015, 'h': .06094,
        'i': .06094, 'j': .00153, 'k': .00772, 'l': .04025,
        'm': .02406, 'n': .06749, 'o': .07507, 'p': .01929,
        'q': .00095, 'r': .05987, 's': .06327, 't': .09056,
        'u': .02758, 'v': .00978, 'w': .02360, 'x': .00150,
        'y': .01974, 'z': .00074, ' ': .13000
    }
	# check every character fequencies and add score and return 0 otherwise
    return sum([character_frequencies.get(chr(byte), 0) for byte in input_bytes.lower()])
	
	
def xor(hex1,key):
  
  b1=unhexlify(hex1)
  xored=bytearray([key^ord(b) for b in b1])
  return xored
#readline() just read single line in file
#readlines() return a list of lines in file
scorelist=[]
#maxlist=[] Note : there is no need  to create a list for max_dict & maxscore of plain english text shall already be the max among all encrypted lines
with open('4.txt') as f:
 for line in f.readlines():
  line=line.strip() # THIS IS A MUST, TAKE CARE
  for i in xrange(256):
   # print"yaaay"  
    plain=xor(line,i)
    pscore=get_english_score(plain)
    data={ 'key':i,'score':pscore,'deciphered':plain }
    scorelist.append(data)
  maxscore=0
  max_dict={}
  for scoreval in scorelist:
   if maxscore<scoreval['score']:
     maxscore=scoreval['score']
     max_dict=scoreval
print ("\n".join("{}\t{}".format(k, v) for k, v in max_dict.items())) 
  #maxlist.append(max_dict)
#print maxlist
#for max in maxlist:
 # print ("\n".join("{}\t{}".format(k, v) for k, v in max.items()))  