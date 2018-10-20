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

# Information of root key digests is taken from "https://data.iana.org/root-anchors/root-anchors.xml"
root_key_digests = ['49AAC11D7B6F6446702E54A1607371607A1A41855200FD2CE1CDDE32F24E8FB5',  'E06D44B80B8F1D39A95C0B0D7C65D08458E880409BBC683457104237C7F8EC8D']

def getLineInfo():
    print(inspect.stack()[1][2])

def iterative_Resolver(domainname):
    
    stime = time.time()
    domainname = dns.name.from_text(domainname)
    default = dns.resolver.get_default_resolver()
    default.timeout=1
    depth = 2
    i=0
    flag = False
    prev_DS_record = []
    is_root = False
    
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
            
            try:
                query = dns.message.make_query(last,dns.rdatatype.A,want_dnssec=True)
                query_response = dns.query.tcp(query, name_server,timeout=3)
                
                dnskey_query = dns.message.make_query(last,dns.rdatatype.DNSKEY,want_dnssec=True)
                dnskey_response = dns.query.tcp(dnskey_query, name_server,timeout=3)
            
                #getLineInfo()
                if is_root == True:
                    ksk = list()
                    if dnskey_response.rcode() == dns.rcode.NOERROR and len(dnskey_response.authority) > 0:
                        for resourcerecord in dnskey_response.authority:
                            if resourcerecord.rdtype == 48:
                                #getLineInfo()
                                rrset = resourcerecord
                                for entry in resourcerecord.items:
                                    if entry.flags == 257:
                                        ksk.append(entry)
                    
                    #getLineInfo()
                    
                    #ksk validation
                    valid = False
                    for rootkey_digest in root_key_digests:
                        if rootkey_digest in ksk:
                            valid = True
                            break
                    
                    #getLineInfo()
                    
                    if valid != True:
                        print "DNSSec verification failed"
                        return

                elif len(query_response.answer)== 0 :
                #RRset - 1
                #RRsig - 2
                #Dnskeys rrset - 3
                    if len(dnskey_response.answer)!=0 and len(query_response.authority) == 3:
                        try:
                            dns.dnssec.validate(response.authority[1], response.authority[2], { dns.name.from_text(last): dnskey_response.answer[0]})
                        except:
                            print "DNSSec verification failed"
                            return
                    else:
                        print "DNSSec not supported"
                        return

                if is_root == True:
                    is_root = False
                elif len(dnskey_response.answer)!=0:
                    flag = False
                    for resourcerecord in dnskey_response.answer:
                        if resourcerecord.rdtype == 48:
                            rrset = resourcerecord
                            for entry in resourcerecord.items:
                                if entry.flags == 257:
                                    currDSrecord1 = dns.dnssec.make_ds(name=last,key=entry,algorithm='SHA1')
                                    currDSrecord2 = dns.dnssec.make_ds(name=last,key=entry,algorithm='SHA256')
                                    curr_DS_record1 = str(currDSrecord1).split(' ')
                                    curr_DS_record2 = str(currDSrecord2).split(' ')
                                    prev_DS_records = str(prev_DS_record).split(' ')
                                    
                                    #validation
                                    for DS_record in curr_DS_record1:
                                        for previous_DS_record in prev_DS_records:
                                            if DS_record == previous_DS_record:
                                                flag = True

                                    if flag == False:
                                        for DS_record in curr_DS_record2:
                                            for previous_DS_record in prev_DS_records:
                                                if DS_record == previous_DS_record:
                                                    flag = True
                    
                    if flag == False:
                        print "DNSSec verification failed"
                        return

                else:
                    print "DNSSec not supported"
                    return


                if len(query_response.authority) == 0:
                    print "DNSSec not supported"
                    return

                else:
                    prev_DS_record = query_response.authority[1]


                if len(dnskey_response.answer)== 2 :
                    try:
                        dns.dnssec.validate(dnskey_response.answer[0], dnskey_response.answer[1], { dns.name.from_text(last): dnskey_response.answer[0]})
                    except:
                        print "DNSSec verification failed"
                        return
                else:
                    print "DNSSec not supported"
                    return
                        
            except:
                print "DNSSec not supported"
                return

            if query_response.rcode() == dns.rcode.NOERROR:
                #getLineInfo()
                resourcerecordset = query_response.authority[0] if (len(query_response.authority) > 0) else query_response.answer[0]

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
        
        if foundip==True:
            return name_server


if __name__=="__main__":
    
    if len(sys.argv)<2:
        print "Arguments are less than 2"
        exit(0)
    
    elif len(sys.argv)>2:
        print "Arguments are greater than 2"
        exit(0)

    auth_name_server = iterative_Resolver(sys.argv[1])

