#!/usr/bin/env python
import json
import networkx as nx
import sys
import angr
import claripy
G=nx.DiGraph()
branch=0
over=0
def stop(pg):
    global over
    if over==1:
        over=0;
        return True
    if len(pg.active)<1:
        return True
    return False
def next(pg):
    global G
    global branch
    successor=pg.step()
    alladdr=[]
    for x in successor:
        alladdr.append(x.addr)
    
    flag=0
    if branch in alladdr:
        print "find the target to test"
        flag=1
    new_successor=[]
    for i in successor:
        if flag==1 and i.addr!=branch:
            print "find another branch!!"
            print hex(i.addr)
            over=1
            f=open(str(i.addr),"w")
            try:
                print i.state.posix.dumps(0)
            except:
                print "no input"
            f.close()
            raw_input()
        if i.addr in G:
            new_successor.append(i)
        elif i.addr>0x600000:
            new_successor.append(i)
        else:
            print "out graph: ",hex(i.addr)
    #print new_successor
    return new_successor



def main():
    global G
    global branch
    binary=angr.Project(sys.argv[2])
    state=binary.factory.entry_state(args=[sys.argv[2],claripy.BVV("-nn -vvv -e -b -H -u -r")])
    replay=json.load(open("replay.json","r"))
    order=open(sys.argv[1]).readlines()
    target={}
    for b,o in replay['target'].items():        
        target[int(b)]=o
    num=0
    while num!=len(order):
        addr=order[num].split(" ")[1]
        addr=addr.split("-")[0]
        print "Now process: "+addr
        path=binary.factory.path(state)
        pg=binary.factory.path_group(path)
        addr=int(addr,16)
        branch=target[addr]['way'][0]
        print "pass to: "+hex(branch)
        G=nx.DiGraph()
        for x in target[addr]["subcfg"]:
            G.add_edge(x[0],x[1])
            #if x[1]==branch :
                #real_target=x[0]
        #print "target block : "+hex(real_target)
        pg.step(successor_func=next,until=stop)
        num+=1
    #print G.edges()
    #print G.nodes()






if __name__ == "__main__":
    main()
