import hashlib
msg=input("enter message: ")
res=hashlib.sha512(msg.encode())
print(res.hexdigest())