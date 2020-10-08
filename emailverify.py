import re
def everify(e):
 regex ="(^[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+$)"
 addressToVerify = str(e)
 match = re.match(regex, addressToVerify)
 if match == None:
  return 0
 else:
  return 1

