from binascii import *

#basic Note : we always work Byte Wise which means we always have to convert hex  to bytes to perform xor
#note: Xor works on binary level so we have to convert each char into int's decimal representation ord('A') and then convert this no into binary
#So to summerize it all xor Doesn't work on a String
#if i enclosed ord(i)^ord(j) in bytes eg: bytes(ord(i)^ord(j)) it will return a list of xored no in "str" form , otherwise in integer form
#bytearray automaticlly converts the "xored decimal representation" into string bytes
 
def xor(hex1,hex2):
  
  b1=unhexlify(hex1)
  b2=unhexlify(hex2)
  xored=bytearray([ord(i)^ord(j) for i,j in zip(b1,b2)])
  print xored
  
xor("1c0111001f010100061a024b53535009181c","686974207468652062756c6c277320657965")