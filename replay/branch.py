#!/usr/bin/env python
import json
import networkx as nx
import sys
def main():
    replay=json.load(open("replay.json","r"))
    order=open(sys.argv[1]).readlines()
    target={}
    for b,o in replay['target'].items():        
        target[int(b)]=o
    addr=order[0].split(" ")[1]
    addr=addr.split("-")[0]
    print addr
    addr=int(addr,16)
    G=nx.DiGraph()
    for x in target[addr]["subcfg"]:
        G.add_edge(x[0],x[1])
    print G.edges()
    print G.nodes()





if __name__ == "__main__":
    main()
