from binascii import *
##key=88
#this simulate bruteforcing single BYTE XOR using english letteres freq analysis
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
  #print "["+`key`+"]"+xored
  return xored
scorelist=[] 
#byte decimal representation 0-255 == 1-256  : therefore we set xrange/range(256) will iterate from 0--> 255
for i in xrange(256): 
  plain=xor("1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736",i)
  pscore=get_english_score(plain)
  #print pscore,"-->"+plain
  data={ 'key':i,'score':pscore,'deciphered':plain }
  scorelist.append(data)
#print scorelist
#to get the list of possible bruteforced keys sorted 
# sorted_scores=sorted(scorelist,key=lambda x: x['score'],reverse=True)
# for score in sorted_scores:
   # print("\n".join("{}\t{}".format(k, v) for k, v in score.items()))#score;break;
#to get maxium score
maxscore=0
max_dict={}
for scoreval in scorelist:
 if maxscore<scoreval['score']:
   maxscore=scoreval['score']
   max_dict=scoreval
print ("\n".join("{}\t{}".format(k, v) for k, v in max_dict.items()))  