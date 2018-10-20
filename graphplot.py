import pandas as pd
import numpy as np
import matplotlib
matplotlib.use('TkAgg')
import matplotlib.pyplot as plt
from matplotlib import pylab
from pylab import *
from pylab import rcParams
rcParams['figure.figsize'] = 12, 10

list1 = ['0.0105053424835', '0.00881106853485', '0.00799806118011', '0.00795726776123', '0.0102604150772', '0.00955243110657', '0.00722150802612', '0.00751087665558', '0.00831301212311', '0.00826179981232', '0.0078803062439', '0.00877318382263', '0.00938487052917', '0.00925464630127', '0.00768051147461', '0.00846843719482', '0.00765976905823', '0.00878643989563', '0.00746040344238', '0.00785691738129', '0.00820925235748', '0.00871350765228', '0.00793373584747', '0.0107094764709', '0.00857429504395']
list2 = ['0.0973369836807', '0.0695210933685', '0.0780107498169', '0.0518876314163', '0.0659055709839', '0.0601086378098', '0.0618573188782', '0.0635358095169', '0.0640582799911', '0.0575918197632', '0.0564335107803', '0.0685418128967', '0.063902926445', '0.0553889274597', '0.0646606206894', '0.0518916368484', '0.0451951980591', '0.0487776756287', '0.0481050252914', '0.0649182081223', '0.0490306615829', '0.0444911718369', '0.0560236930847', '0.0479331970215', '0.0459890604019']
list3 = ['0.353014349937', '0.409842920303', '0.432399129868', '0.700040316582', '0.477601623535', '0.342815136909', '0.374724030495', '0.756887888908', '0.628175258636', '0.414785504341', '0.378340363503', '0.430775785446', '0.329068231583', '0.72980837822', '0.320581030846', '0.337737798691', '0.478205943108', '0.744131278992', '2.72896294594', '0.858358716965', '0.757789182663', '1.22399289608', '0.520557522774', '0.431894278526', '0.971626329422']
website = ['google.com','youtube.com','facebook.com','baidu.com','wikipedia.org','reddit.com', 'yahoo.com','google.co.in','Qq.com','Toabao.com','amazon.com',
           'Tmall.com','Twitter.com','google.co.jp','instagram.com','live.com','Vk.com', 'Sohu.com','Sina.com.cn', 'jd.com','Weibo.com','360.cn','google.de','google.co.uk', 'google.com.br']


list1_float = []
list2_float = []
list3_float = []

for values in list1:
    list1_float.append(float(values))
for values in list2:
    list2_float.append(float(values))
for values in list3:
    list3_float.append(float(values))

web1 = np.cumsum(list1_float)
web2 = np.cumsum(list2_float)
web3 = np.cumsum(list3_float)



listnum = []
for i in range(0,25):
    listnum.append(i)
plt.yticks(listnum,website,rotation=20)
plt.plot(web1,listnum,c='green',label='Local DNS Resolver')
plt.plot(web2,listnum,c='blue',label='Google DNS Resolver')
plt.plot(web3,listnum,c='red',label='My DNS Resolver')
np.roll(website,-1)
plt.legend(loc='lower right')

plt.ylabel('     CDF                     Alexa Top 25 Websites List')
plt.xlabel('Resolution Time (in sec)')
#plt.set_size_inches(12.5, 12.5, forward=True)
pylab.savefig('CDF.png')
plt.show()
