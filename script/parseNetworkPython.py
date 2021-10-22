import pyshark
from statistics import mean

lenght = 0
counter = 0
packages = []
package_lost = []
packages_size = []
package_lost_counter = 0
small_size = 100
large_size = 400
global qos

small = 'small'
medium = 'medium'
large = 'large'

package_lost_limit = 2
max_size_packages = 6
best_protocols = {small: 'coap', medium: 'mqtt0', large: 'mqtt2'}
best_protocols_numbers = {'1': 'COAP', '2': 'MQTT 0', '3': 'MQTT2'}

mqtt_qos_level = {
    'At most once delivery (Fire and Forget)': 0,
    'At least once delivery (Acknowledged deliver)': 1,
    'Exactly once delivery (Assured Delivery)': 2}

coap_package_size = {small: 100, large: 460}
mqtt0_package_size = {small: 100, large: 1000}
mqtt1_package_size = {small: 100, large: 730}
mqtt2_package_size = {small: 100, large: 470}


# Capture data from network
networkInterface = "en0"
filter_CoAP_MQTT = "(dst port 5683 or src port 5683) or (dst port 1883 or src port 1883)"

captureFullPackage = pyshark.LiveCapture(
    interface=networkInterface, bpf_filter=filter_CoAP_MQTT)
captureSummary = pyshark.LiveCapture(
    interface=networkInterface, bpf_filter=filter_CoAP_MQTT, only_summaries=True)

print("listening on %s" % networkInterface)

class Package(object):
    def __init__(self, size, time, protocol, qos):
        self.size = size
        self.time = time
        self.protocol = protocol
        self.qos = qos

def createPackage(size, time, protocol, qos):  
    print('qos ', qos, ' | size ', size)
    return Package(int(size), float(time), protocol, int(qos))


def getPackageSize(package):
    if (package.size):
        return package.size
    else:
        return 0


def is_packet_lost(captureFullPackage, protocol):
    if (protocol == 'mqtt' and hasattr(captureFullPackage, 'tcp')):
        return captureFullPackage.tcp.analysis.flags is not None
    elif(hasattr(captureFullPackage, 'coap')):
        return captureFullPackage.coap.retransmitted and captureFullPackage.coap.block.error


def calculate_package_size_average(packages):
    return mean(list(map(getPackageSize, packages)))


def calculate_total_time(packages):
    totalTimePackage = []
    for packaage in packages:
        totalTimePackage.append(packaage.time)
    return sum(totalTimePackage)


def identify_package_size(package_size):
    if (package_size <= small_size):
        return small
    if (package_size > small_size and package_size <= large_size):
        return medium
    if (package_size > large_size):
        return large

def refactor_identify_package_size(package):
    result = 1
    #COAP Protocol
    if(package.protocol == 'CoAP'):
        if(package.size <= coap_package_size[small]):
            result = 1
        elif( package.size > coap_package_size[large] ):
            result = 2
        elif( (package.size > coap_package_size[small]) and (package.size <= coap_package_size[large]) ):
            result = 3

    #MQTT Protocol
    if((package.protocol == 'MQTT' or package.protocol == 'TCP') and package.qos == 0):
        if( package.size <= mqtt0_package_size[small]):
            result = 1
        elif( (package.size > mqtt0_package_size[small]) and (package.size <= mqtt0_package_size[large]) ):
            result = 2.5
        elif( package.size > mqtt0_package_size[large]):
            result = 6.3

    elif((package.protocol == 'MQTT' or package.protocol == 'TCP') and package.qos == 1):
        if( package.size <= mqtt1_package_size[small] ):
            result = 1
        elif( (package.size > mqtt1_package_size[small]) and (package.size <= mqtt1_package_size[large]) ):
            result = 2.5
        elif( package.size > mqtt1_package_size[large]):
            result = 6.3

    elif((package.protocol == 'MQTT' or package.protocol == 'TCP') and package.qos == 2):
        if( package.size <= mqtt2_package_size[small] ):
            result = 1
        elif( (package.size > mqtt2_package_size[small]) and (package.size <= mqtt2_package_size[large]) ):
            result = 2.5
        elif( package.size > mqtt2_package_size[large]):
            result = 6.3

    elif((package.protocol == 'MQTT' or package.protocol == 'TCP') and package.qos == 3):
        if( package.size <= mqtt1_package_size[small] ):
            result = 1
        elif( (package.size > mqtt1_package_size[small]) and (package.size <= mqtt2_package_size[large]) ):
            result = 2.5   
        elif( package.size > mqtt2_package_size[large]):
            result = 6.3
    print('result - ', result)                  
    return result        

# Identify the best protocol based on network conditions
for captureFullPackage, captureSummary in zip(captureFullPackage.sniff_continuously(), captureSummary.sniff_continuously()):

    # if(is_packet_lost(captureFullPackage, captureSummary.protocol)):
    #     package_lost_counter += 1

    if(counter < max_size_packages):
        qos = 3
    
        if(captureSummary.protocol == 'MQTT' or captureSummary.protocol == 'CoAP' or captureSummary.protocol == 'TCP'):

            if(captureSummary.protocol == 'MQTT' or captureSummary.protocol == 'TCP'):
                qos = 3 if captureSummary.qos == '' else mqtt_qos_level[str(captureSummary.qos)]

            #Has any lost package?
            if(hasattr(captureFullPackage, '_ws.malformed')):
                current_package = createPackage(captureFullPackage.mqtt.len, captureSummary.time, captureSummary.protocol, qos)
            else:
                current_package = createPackage(captureSummary.length, captureSummary.time, captureSummary.protocol, qos)    
            
            current_package_complet = refactor_identify_package_size(current_package)
            packages.append(current_package)
            packages_size.append(current_package_complet)
            counter += 1
    else:
        package_size_avr = calculate_package_size_average(packages)

        package_size = identify_package_size(package_size_avr)

        # package_total_time = calculate_total_time(packages)

        final_size = package_size
        the_best =   round(mean(packages_size))
        print(list(packages_size))

        if(the_best > 3):
            the_best = 3

        if(the_best < 1):
            the_best = 1

        print('----------')
        print( best_protocols_numbers[ str(the_best) ], ' - ', the_best )
        print('----------')

        packages = []
        packages_size = []
        counter = 0
        # package_lost_counter = 0
        packages.append(current_package)
        packages_size.append(current_package_complet)

        # # There is package lost
        # if(hasattr(captureFullPackage.tcp, 'analysis')):

        #     if((len(package_lost_counter) > package_lost_limit) and (package_size == small or package_size == medium)):
        #         if(package_size == small and (package_size_avr >= 90 and package_size_avr <= 100)):
        #             final_size = medium

        #         if(package_size == medium and (package_size_avr > 400 and package_size_avr < 500)):
        #             final_size = large

        # print(best_protocols[final_size])
