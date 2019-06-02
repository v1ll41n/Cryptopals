from binascii import hexlify
#CryptoPlas CH15 Set2
#PKCS#7 padding validation
'''
Idea is simple to unpad a padded string you have to do the following:
1-Determin the padding size ,how? by simply reading the **last** byte of the padded string and convert it from hex value back into a decimal number (recall padding bytes are always hex vals)
you can do this using int(hex(),16)

2-now to check is the padding is *valid* or not we simply read the last N bytes from padded data where N is the decimal value of padding we already got in prev step
now simply compare the len(last N bytes) with the decimal (N) if they are equal then padding is valid if not , then padding is invalid

3-Now to unpad the padding text you just **CUT/SLice** the last N bytes from your input string using slicing padded_data[:-N]


'''
def get_pad_val(padded_data):
  return int(hexlify(padded_data[len(padded_data)-1:]),16) #or padded_data[-1:] 

def pkcs7_padding(data,blocksize):

 pad_size=(blocksize-len(data))%blocksize
 if pad_size==0: 
   pad_size=blocksize
 #print "pad_size="+`pad_size`
 padded_data=data+chr(pad_size)*pad_size
 
 return padded_data 

def unpad(padded_data,pad_val):
  return padded_data[:-pad_val]
 
def validate_padding(padded_data):

   pad_val=get_pad_val(padded_data)
   print "[+]Padding size="+`pad_val`
   padding_bytes=padded_data[-pad_val:]
   if len(padding_bytes)==pad_val:
      print"[+]Padding is valid"
      unpadded_data=unpad(padded_data,pad_val)
      print "[+]Unpadded Data ="+unpadded_data
	  
   else :
       print "[-]Invalid Padding"

validate_padding(pkcs7_padding("NOPs Never Die",16))