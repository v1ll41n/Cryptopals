from binascii import *

#1)determine the length of the key 
#2)determine the length of message
#3)make the key length = message length by repeating key over and over again (multiplicity)
#4)make a normal xor operation


def rexor(Message,key):
  diff=len(Message)-len(key)
  if(diff>0):
    key=key*diff #repeating key (n) times where n is the diff between message length and key length
    res=hexlify(bytearray([ord(i)^ord(j) for i,j in zip(key,Message)]))
    return res
Message="Burning 'em, if you ain't quick and nimble \
         I go crazy when I hear a cymbal"
print rexor(Message,'ICE')
	

