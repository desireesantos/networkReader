import pyshark
from influxdb import InfluxDBClient

host = 'localhost'
port = 8086

networkInterface = "en0"
filter = "dst port 5683"

client = InfluxDBClient(host, port)
client.switch_database('middleware')

captureFullPackage = pyshark.LiveCapture(interface=networkInterface, bpf_filter=filter)
captureSummary = pyshark.LiveCapture(interface=networkInterface, bpf_filter=filter, only_summaries=True)

print("listening on %s" % networkInterface)

for captureFullPackage,captureSummary in zip(captureFullPackage.sniff_continuously(), captureSummary.sniff_continuously()):

    try:
        transport_layer = captureFullPackage.transport_layer    # protocol transport_layer
        src_addr = captureFullPackage.ip.src                    # source address
        dst_addr = captureFullPackage.ip.dst                    # destination address
        protocol = captureSummary.protocol                      # protocol 
        info = captureSummary.info                              # wireshark summary info
        time = captureSummary.time                              # package time

        json_body = [
        {
            "measurement": "middleware",
            "fields": {
                "transport_layer": transport_layer,
                "src_addr": src_addr,
                "dst_addr": dst_addr,
                "protocol": protocol,
                "info": info,
                "packet_time": time
            }
        }
    ]   
        client.write_points(json_body) 
        # print ("(%s - %s) IP %s:%s - %s" % (protocol, transport_layer, src_addr,dst_addr, info))
        # print("Write points: {0}".format(json_body))

    except AttributeError as e:
        pass
    print (" ")