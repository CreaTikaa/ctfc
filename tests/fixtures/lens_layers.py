import base64, zlib

K = b'L4y3rs!'
D = "eJyzcROIZYtm5s+1ruUU9TBx4HEU1/HVjOLKYeIKVYkWz5ETitB04/ILiNIGALfdCL8="

raw = zlib.decompress(base64.b64decode(D))
out = bytes(b ^ K[i % len(K)] for i, b in enumerate(raw))
exec(out)
