import base64

i=raw_input("please Enter the string >> ")
i=i.decode('hex')
print base64.b64encode(i)