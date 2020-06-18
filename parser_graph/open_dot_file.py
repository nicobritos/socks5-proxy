from graphviz import Source
import sys

if(len(sys.argv) != 2):
    raise Exception('Uso del archivo: "open_dot_file /path/to/file"')
path = sys.argv[1]
s = Source.from_file(path)
s.view()
