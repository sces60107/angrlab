#!/usr/bin/env python

import json
import networkx as nx
from networkx.readwrite import json_graph


def main():
    small=1000000
    smalladdr=0
    replay = json.load(open('replay.json',"r"))
    unigraph=json_graph.node_link_graph(replay['unigraph'])
    target=dict()
    lensort={}
    for branch,obj in replay['target'].items():
        target[int(branch)]=obj
    for branch,obj in target.items():
        lensort[len(obj['subcfg'])]=[branch,obj['way'][0]]
        #print'branch: %x->%x'%(branch, obj['way'][0])+' # of subcfg edges: %d'%len(obj['subcfg'])
    ss=sorted(lensort)
    for x in ss: 
        print'branch: %x->%x'%(lensort[x][0],lensort[x][1])+' # of subcfg edges: %d'%x



if __name__ == "__main__":
    main()
