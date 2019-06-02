'''
Block cipher modes for symmetric-key encryption algorithms require plain text input that is a multiple of the block size, 
so messages may have to be padded to bring them to this length.
In PKCS#7 padding, padding is in whole bytes. 
The value of each added byte is the number of bytes that are added, 
i.e. N bytes, each of value N are added. 
The number of bytes added will depend on the block boundary(block size) to which the message needs to be extended.

The padding will be one of:
01
02 02
03 03 03
04 04 04 04
05 05 05 05 05
06 06 06 06 06 06

###Note### :
we are padding using HEX values of N where N is the no of bytes added to complete the padding to blocksize
E.g padding('hey this is selim',34) to PAD this string we need to add 34-17 ==> 17 padding bytes but 17 HEX representation is x11
so the result will be 'hey this is selim+(\x11)*17' ==> 'hey this is selim\x11\x11\x11\x11\x11\x11\x11\x11\x11\x11\x11\x11\x11\x11\x11\
1\x11'

if the msg has the same length of block size we then padd the message with padding lenght = msg length or blocksize (both are equal)
E.g: padding('hey this is Kselim',18) since size of our msg equals the size of blocksize so this will pad our message with 18 bytes
the hex representation of 18 is 0x12 so the rsult will be ('hey this is Kselim'+(\x12)*18)
'hey this is Kselim\x12\x12\x12\x12\x12\x12\x12\x12\x12\x12\x12\x12\x12\x12\x12\x12\x12\x12'
'''
def pkcs7_padding(data,blocksize):

 pad_size=(blocksize-len(data))%blocksize#to keep padding_size within block boundries
 if pad_size==0: 
   pad_size=blocksize#set the pad_size the same as data length==blocksize
 padded_data=data+chr(pad_size)*pad_size #we use chr() instead which returns the hex representation of number
 return padded_data
 
print pkcs7_padding("YELLOW SUBMARINE",20)