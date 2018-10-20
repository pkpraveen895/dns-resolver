import sys
import dns
import time
import dns.opcode
import dns.resolver
import dns.query
import dns.name
import dns.rcode
import dns.flags
import inspect
import re
import string

i=0
stime = 0 # initialise time - used to find the total time taken to find the ip address
#file1 = open("check.txt","wb")

# Information of root servers is taken from "https://www.iana.org/domains/root/servers"
rootservers = ["193.0.14.129","192.33.4.12","192.36.148.17","192.5.5.241","202.12.27.33","199.7.91.13","192.58.128.30","192.228.79.201","198.97.190.53","192.203.230.10","199.7.83.42","198.41.0.4","192.112.36.4"]

alexa_top_25_websites = ['google.com','youtube.com','facebook.com','baidu.com','wikipedia.org','reddit.com', 'yahoo.com','google.co.in','Qq.com','Toabao.com','amazon.com',
                         'Tmall.com','Twitter.com','google.co.jp','instagram.com','live.com','Vk.com', 'Sohu.com','Sina.com.cn', 'jd.com','Weibo.com','360.cn','google.de','google.co.uk', 'google.com.br']

def getLineInfo():
    print(inspect.stack()[1][2])

def check_perf():
    f = open("cumulative_output.txt","wb")
    for site in alexa_top_25_websites:
        totaltime = 0.0
        cnt=0
        avg_time = {}
        while (cnt<10):
            start_time = time.time()
            auth_name_server = iterative_Resolver(site)
            '''query = dns.message.make_query(domainname, dns.rdatatype.from_text(recordtype))
    
            try:
                auth_name_server = dns.query.udp(query, '8.8.8.8',timeout=3) #google resolver
                #auth_name_server = dns.query.udp(query, '192.168.43.1',timeout=3) #local dns resolver
            except:
                print "error"'''

            if auth_name_server!=None:
                totaltime = totaltime + (time.time()-start_time)
                cnt = cnt + 1
        if cnt!=0:
            avg_time[site]=(totaltime/cnt)
        else:
            avg_time[website]=0
        f.write("\nwebsite: %s" %site)
        f.write("\navg time: ")
        f.write("%s" %avg_time[site])
        f.write(" sec\n")

    f.close()

def iterative_Resolver(domainname):
    
    stime = time.time()
    domainname = dns.name.from_text(domainname)
    default = dns.resolver.get_default_resolver()
    depth = 2
    default.timeout=1
    i=0
    flag = False
    
    for i in rootservers:
        name_server = i
        foundip=False
        #file1.write("\n prev : %s" %name_server)
        
        while not flag:
            #getLineInfo()
            domainnamesplit = domainname.split(depth)
            last = domainnamesplit[1]
            first = domainnamesplit[0]
            flag = first.to_unicode() == u'@'
            
            query = dns.message.make_query(last,dns.rdatatype.NS)
            response = dns.query.udp(query, name_server)

            if response.rcode() == dns.rcode.NOERROR:
                #getLineInfo()
                resourcerecordset = response.authority[0] if (len(response.authority) > 0) else response.answer[0]

                resourcerecord = resourcerecordset[0]
                
                if(resourcerecord.rdtype != dns.rdatatype.SOA):
                    #getLineInfo()
                    authority = resourcerecord.target
                    query = dns.message.make_query(domainname, dns.rdatatype.A)
                    name_server = default.query(authority).rrset[0].to_text()
                    
                    try:
                        #getLineInfo()
                        response = dns.query.udp(query,name_server,timeout=3)
                        
                        for x in response.answer:
                            #getLineInfo()
                            foundip=True
                
                    except:
                        print "Exception Occured"
                        break
        
            else:
                return None
            
            depth += 1
        
        if foundip == True:
            #getLineInfo()
            return name_server


if __name__=="__main__":
    
    if len(sys.argv)<3:
        print "Arguments are less than 3"
        exit(0)
    
    elif len(sys.argv)>3:
        print "Arguments are greater than 3"
        exit(0)

    f = open("mydig_output1.txt","wb")
    starttime = time.time()
    auth_name_server = iterative_Resolver(sys.argv[1])
    recordtype = sys.argv[2]

    domainname = dns.name.from_text(sys.argv[1])

    query = dns.message.make_query(domainname, dns.rdatatype.from_text(recordtype))
    response=None

    try:
        response = dns.query.tcp(query, auth_name_server,timeout=3)

    except:
        print "Exception Occured"

    if response!=None:
        print
        f.write("\nid: %s" %response.id)
        print "id: %s" %response.id
        f.write("\nopcode: %s" %dns.opcode.to_text(response.opcode()))
        print "opcode: %s" %dns.opcode.to_text(response.opcode())
        f.write("\nrcode : %s" %dns.rcode.to_text(response.rcode()))
        print "rcode : %s" %dns.rcode.to_text(response.rcode())
        f.write("\nflags: %s" %dns.flags.to_text(response.flags))
        print "flags: %s" %dns.flags.to_text(response.flags)
        print
        f.write("\nQuestion:" % response.question)
        print "Question:"
        for x in response.question:
            f.write("\n")
            f.write(str(x))
            print(str(x))
        print
        f.write("\nAnswer:")
            
        if response.answer!=None:
            print "Answer:"
            for nameserver in response.answer:
                f.write("\n")
                f.write(str(nameserver))
                print(str(nameserver))
            print

        f.write("\nAuthority:")
        if response.authority!=None:
            print "Authority:"
            for x in response.authority:
                f.write("\n")
                f.write(str(x))
                print(str(x))
            print

        f.write("\nAdditional: %s" % response.additional)
        endtime = time.time()
        f.write("\nQuery time: ")
        print "Query Time: {}ms".format((time.time()-starttime) * 1000)
        f.write("%s" %(time.time()-starttime))
        f.write(" sec\n")
        f.write("\nWHEN: {}".format(time.asctime(time.localtime(time.time()))))
        print "WHEN: {}".format(time.asctime(time.localtime(time.time())))
        f.write("\nMSG SIZE rcvd: %s" %len(response.to_text()))
        print "MSG SIZE rcvd:",len(response.to_text())
        f.close()

    #check_perf()
    #file1.close()

