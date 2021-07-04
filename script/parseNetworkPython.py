import pyshark
from influxdb import InfluxDBClient

host = 'localhost'
port = 8086
json_body = []
networkInterface = "en0"
filter_CoAP_MQTT = "dst port 1883 or dst port 5683"

client = InfluxDBClient(host, port)
client.switch_database('middleware')

captureFullPackage = pyshark.LiveCapture(interface=networkInterface, bpf_filter=filter_CoAP_MQTT)
captureSummary = pyshark.LiveCapture(interface=networkInterface, bpf_filter=filter_CoAP_MQTT, only_summaries=True)

print("listening on %s" % networkInterface)

def buildMQTTJson(captureFullPackage, captureSummary):
        transport_layer = captureFullPackage.transport_layer    # protocol transport_layer
        src_addr = captureFullPackage.ip.src                    # source address
        dst_addr = captureFullPackage.ip.dst                    # destination address
        protocol = captureSummary.protocol                      # protocol 
        package_time = captureSummary.time                      # package time
        status = captureSummary.info
    
        payload_size = captureFullPackage.mqtt.len
        mid = captureFullPackage.mqtt.msgid
        method_type = captureFullPackage.mqtt.msgtype
        uri_path = captureFullPackage.mqtt.topic
        qos = captureFullPackage.mqtt.sub_qos

        json_body = [
            {
                "measurement": "middleware",
                "fields": {
                    "transport_layer": transport_layer,
                    "protocol": protocol,
                    "payload_size": payload_size,
                    "src_addr": src_addr,
                    "dst_addr": dst_addr,
                    "status": status,
                    "mid": mid,
                    "method_type": method_type,
                    "uri_path": uri_path,
                    "package_time": package_time,
                    "qos": qos
                }
            }
        ]
        return json_body

def buildCoAPJson(captureFullPackage,captureSummary):
            transport_layer = captureFullPackage.transport_layer    # protocol transport_layer
            payload_size = captureFullPackage.coap.payload_length
            src_addr = captureFullPackage.ip.src                    # source address
            dst_addr = captureFullPackage.ip.dst                    # destination address
            protocol = captureSummary.protocol                      # protocol 
            package_time = captureSummary.time                      # package time
            
            package_info = captureSummary.info.split(",")                              # wireshark summary info
            status = package_info[0].strip()
            mid = package_info[1].strip()
            method_type = package_info[2].strip()
            uri_path = package_info[3].strip()

            json_body = [
                {
                    "measurement": "middleware",
                    "fields": {
                        "transport_layer": transport_layer,
                        "protocol": protocol,
                        "payload_size": payload_size,
                        "src_addr": src_addr,
                        "dst_addr": dst_addr,
                        "status": status,
                        "mid": mid,
                        "method_type": method_type,
                        "uri_path": uri_path,
                        "package_time": package_time
                    }
                }
            ]
            return json_body


for captureFullPackage,captureSummary in zip(captureFullPackage.sniff_continuously(), captureSummary.sniff_continuously()):

    try:
        if captureSummary.protocol == 'CoAP':
            json_body =  buildCoAPJson(captureFullPackage,captureSummary)
        else:
            json_body =  buildMQTTJson(captureFullPackage,captureSummary)      
        
        client.write_points(json_body) 
        # print("Write points: {0}".format(json_body))
        
    except AttributeError as e:
        pass
    print (" ")