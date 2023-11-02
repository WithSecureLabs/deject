from pdf2image import convert_from_path, convert_from_bytes
import argparse
parser = argparse.ArgumentParser()
parser.add_argument("pdf")
parser.add_argument("output")
args = parser.parse_args()
pdf = args.pdf
out = args.output
images = convert_from_path(pdf)
i=0
if not str(out).endswith('/'):
	out += '/'
for image in images:
	i+=1
	image.save(''+str(out)+''+str(i)+'.jpg','JPEG')
