from Crypto.Cipher import AES

def encrypt_aes_ecb(PT):
 randkey='YELLOW SUBMARINE' #urandom(16)
 encipher=AES.new(randkey,AES.MODE_ECB)
 return  encipher.encrypt(pkcs7_padding(PT,16))
 
def pkcs7_padding(data,blocksize):

 pad_size=(blocksize-len(data))%blocksize#to keep padding_size within block boundries
 if pad_size==0: 
   pad_size=blocksize#set the pad_size the same as data length==blocksize
 padded_data=data+chr(pad_size)*pad_size #we use chr() instead which returns the hex representation of number
 return padded_data
 
 
def decrypt_aes(Msg):
 Key='YELLOW SUBMARINE'
 CT=AES.new(Key,AES.MODE_ECB)
 pt=CT.decrypt(Msg)
 return pt
 
def k_v_parsiong_routine(encoded):
   dict={}
   encoded=encoded.split('&') #replcament for explode in php
   for pair in encoded:
        i,j = pair.split('=')
        dict[i]=j
   return dict
  
def profile_for(email):
 email=email.replace('&','') #filter out any & char
 email=email.replace('=','') #filter out any = char
 d={'uid':10,'email':email,'role':'user'}
 return '&'.join(['%s=%s' % (k,d[k]) for k in d][::-1]) #[::-1] for reversing the list,thus making it in right order email,uid,role
 
  
def ecb_cut_paste(email):
  email_prefix=email[:10] #get the first 10 bytes to complete first block
  email_postfix=email[10:] #put the left 3 bytes after the second block
  evil_payload=profile_for(email_prefix+pkcs7_padding('admin',16)+email_postfix)
  hijacked_role=encrypt_aes_ecb(evil_payload)[16:32] #get the second enc block only (admin block)[CUT]
  normal_profile=encrypt_aes_ecb(profile_for(email))[:32] #encrypt email normally and get the first two blocks(email&uid)
  hijacked_profile=normal_profile+hijacked_role#paste your slices together [PASTE]
  return  decrypt_aes(hijacked_profile)

print ecb_cut_paste('Nops@NOPs.com')  #13 bytes email
#print k_v_parsiong_routine("k=nops&email=kaito@fck.me&prof=NOOB")
#print profile_for('kimo@nops.com')