import pyshark

networkInterface = "en0"
filter="dst port 5683"

captureFullPackage = pyshark.LiveCapture(interface=networkInterface, bpf_filter=filter)
captureSummary = pyshark.LiveCapture(interface=networkInterface, bpf_filter=filter, only_summaries=True)

print("listening on %s" % networkInterface)

for captureFullPackage,captureSummary in zip(captureFullPackage.sniff_continuously(), captureSummary.sniff_continuously()):

    try:
       
        transport_layer = captureFullPackage.transport_layer    # protocol transport_layer
        src_addr = captureFullPackage.ip.src                    # source address
        dst_addr = captureFullPackage.ip.dst                    # destination address

        protocol = captureSummary.protocol                      # protocol 
        info = captureSummary.info                              # source port

        print ("(%s - %s) IP %s:%s - %s" % (protocol, transport_layer, src_addr,dst_addr, info))

    except AttributeError as e:
        pass
    print (" ")