#!/usr/bin/env python
import json
import networkx as nx
import sys
import angr
import claripy
import time
import os.path
G=nx.DiGraph()
nowtime=0
timeout=600
need=False
Distance={}
branch=0
over=0
pending_state=[]
real_target=0
logfilename="Bangrlog"
processlogfilename="Bcountlog"
targetblock=0
def processlog(message):
    temp=open(processlogfilename,"a")
    temp.write(time.ctime()+" "+message+"\n")
    temp.close()
    log(message)
def log(message):
    temp=open(logfilename,"a")
    temp.write(time.ctime()+" "+message+"\n")
    temp.close()
def stop(pg):
    global over
    global pending_state
    global nowtime
    global timeout
    if over==1:
        over=0
        return True
    if time.time()-nowtime>timeout:
        processlog("timeout!")
        return True
    if len(pg.stashes["active"])<1:
        if len(pending_state)<1:
            return True
        else:
            pg.stashes["active"]=pending_state
            pending_state=[]
            log("I am here")
            return false
    return False
def check_file(name):
    count=0
    while os.path.isfile(name+str(count)):
        count+=1
    return open(name+str(count),"w")
    
def next(pg):
    global pending_state
    global G
    global branch
    global real_target
    global timeout
    global need
    global over
    successor=pg.step()
    alladdr=[]
    bound=10000000000
    #print successor
    for x in successor:
        alladdr.append(x.addr)
        if x.addr in G and Distance[x.addr]<bound:
            bound=Distance[x.addr]
    #print bound
    flag=0
    if branch in alladdr:
        log("find the target to test")
        flag=1
    new_successor=[]

        
    for i in successor:
        if flag==1 and i.addr!=branch:
            log("find another branch!!")
	    #print real_target
            #print hex(i.addr)
            over=1
            try:
		#print i.state.posix.dumps(0)
		if len(i.state.posix.dumps(0))==0:
			print "no len input"
		else:
			processlog( i.state.posix.dumps(0).encode("hex"))
			processlog("we found it")
                        processlog(str(time.time()-nowtime))
                        f=check_file("Bnew/0x"+real_target+"->"+hex(i.addr))
			#f=open("Bnew/0x"+real_target+"->"+hex(i.addr),"w")
                        if (time.time()-nowtime)*1.5>timeout:
                            need=True
			f.write(i.state.posix.dumps(0))
			f.close()
            except:
                log("no input")
        if i.addr in G:
            if Distance[i.addr]<=bound:
                new_successor.append(i)
            else:
                pending_state.append(i)
        elif i.addr>0x600000:
            new_successor.append(i)
        #else:
            #print "out graph: ",hex(i.addr)
    #print new_successor
    if len(new_successor)==0:
        new_successor=pending_state
        pending_state=[]
        #log("add pending")
    return new_successor
def GraphWithDistance(subG):
    global Distance
    global targetblock
    distance=0
    Distance={}
    array=[targetblock]
    #print subG.nodes()
    while len(array)!=0:
        new_array=[]
        for x in array:
            Distance[x]=distance
            #print subG.neighbors(x)
            for y in subG.neighbors(x):
                if y not in Distance:
                    new_array.append(y)
                    #print y
        distance+=1
        array=new_array
        #print array
def findtargetblock(subG,addr,branch):
    global targetblock
    targetblock=0
    for x in subG.nodes():
        if x<=addr and x>targetblock:
            targetblock=x
    return
    
def main():
    global G
    global pending_state
    global branch
    global real_target
    global nowtime
    global need
    global timeout
    print len(sys.argv)
    if len(sys.argv)!=4:
	print "Usage: ./branch-heuristic.py order-file binary-file json-file"
	exit()
    binary=angr.Project(sys.argv[2])
    state=binary.factory.entry_state(args=[sys.argv[2],claripy.BVV("-nn"),claripy.BVV("-vvv"),claripy.BVV("-e"),claripy.BVV("-b"),claripy.BVV("-H"),claripy.BVV("-u"),claripy.BVV("-r"),claripy.BVV("-")])
    replay=json.load(open(sys.argv[3],"r"))
    order=open(sys.argv[1]).readlines()
    target={}
    for b,o in replay['target'].items():        
        target[int(b)]=o
    num=0
    while num!=len(order):
        if need:
            timeout+=100
            need=False
        addr=order[num].split(" ")[1]
        addr=addr.split("-")[0]
	real_target=addr
        processlog("Now process: "+addr)
        path=binary.factory.path(state)
        pg=binary.factory.path_group(path)
        addr=int(addr,16)
        branch=target[addr]['way'][0]
        processlog("pass to: "+hex(branch))
        G=nx.Graph()
        for x in target[addr]["subcfg"]:
            G.add_edge(x[0],x[1])
            #if x[1]==branch :
                #real_target=x[0]
        findtargetblock(G,addr,branch)
        GraphWithDistance(G)
        #print targetblock
        #print Distance
        #raw_input()
        pending_state=[]
        nowtime=time.time()
        #print "target block : "+hex(real_target)
        pg.step(successor_func=next,until=stop)
        num+=1
    #print G.edges()
    #print G.nodes()






if __name__ == "__main__":
    main()
