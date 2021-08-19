import pyshark
from influxdb import InfluxDBClient
from statistics import mean

host = 'localhost'
port = 8086
result = []
networkInterface = "en0"
filter_CoAP_MQTT = "(dst port 5683 or src port 5683) or (dst port 1883 or src port 1883)"

lenght = 0
small_size = 100
large_size = 500
package_lost_limit = 2

client = InfluxDBClient(host, port)
client.switch_database('middleware')

captureFullPackage = pyshark.LiveCapture(interface=networkInterface, bpf_filter=filter_CoAP_MQTT)
captureSummary = pyshark.LiveCapture(interface=networkInterface, bpf_filter=filter_CoAP_MQTT, only_summaries=True)

print("listening on %s" % networkInterface)
class Package(object):  
    def __init__(self,size):
        self.size=size

def getPackageSize(package):
    if (package.size):
        return package.size
    else:
        return 0    

def calculate_package_size_average(packages):
    return mean( list(map(getPackageSize, packages)) )

def identify_package_size(package_size):
    if (package_size <= small_size): return 'SMALL'
    if (package_size > small_size and package_size <= large_size): return 'MEDIUM'
    if (package_size > large_size): return 'LARGE'    

for captureFullPackage,captureSummary in zip(captureFullPackage.sniff_continuously(), captureSummary.sniff_continuously()):
    lenght = captureSummary.length

    if( hasattr(captureFullPackage,'mqtt')):
        lenght = captureFullPackage.mqtt.len
  
    if(len(result) < 4):
      result.append( Package( int(lenght) ))
    else:
       package_size_avr = calculate_package_size_average(result)
       print(identify_package_size(package_size_avr))
       result = []
       result.append( Package(int(lenght)) )