from html.parser import HTMLParser

class docparser(HTMLParser):
    def __init__(self, *, convert_charrefs=True):
        self.reset()
        self.convert_charrefs = convert_charrefs
        self.print = False
    def handle_starttag(self, tag, attrs):
        if tag == "div":
            for (attr, value) in attrs:
                self.print = (attr == "class") and (value == "col1")
        # self.print = (tag == "div" & attrs["class"] == "col1")
    def handle_data(self, data):
        if self.print:
            print(data, end='')
    def handle_endtag(self, tag):
        self.print &= (tag == "dig")

f = open("manual.tmp")
data = f.read
parser = docparser()
for line in f:
    parser.feed(line)

