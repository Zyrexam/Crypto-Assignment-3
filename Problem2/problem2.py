
import sys
import ast
import random
from PIL import Image

what = sys.argv[1]
img = Image.open(sys.argv[2])
sz = img.size
print(sz)

out = sys.argv[3]

if len(sys.argv) <= 4:
  perm = list(range(sz[0] * sz[1]))
  random.shuffle(perm)
  open("perm.key", "w").write(str(perm))
  print("Generated key: perm.key")
else:
  perm = ast.literal_eval(open(sys.argv[4]).read())

if what == "decrypt":
  old = perm
  perm = list(range(sz[0] * sz[1]))
  for i, x in enumerate(old):
    perm[x] = i
elif what != "encrypt":
  print("Wrong usage!")
  sys.exit()

pixels = list(img.getdata())
new = pixels[:]
for i, x in enumerate(perm):
  new[i] = pixels[x]

img.putdata(new)
img.save(out)
