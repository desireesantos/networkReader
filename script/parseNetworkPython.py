import pyshark
from statistics import mean

lenght = 0
counter = 0
packages = []
small_size = 100
large_size = 400

small = 'SMALL'
medium = 'MEDIUM'
large = 'LARGE'

package_lost_limit = 2
max_size_packages = 10
best_protocols = {small: 'coap', medium: 'mqtt0', large: 'mqtt2'}


# Capture data from network
networkInterface = "en0"
filter_CoAP_MQTT = "(dst port 5683 or src port 5683) or (dst port 1883 or src port 1883)"

captureFullPackage = pyshark.LiveCapture(
    interface=networkInterface, bpf_filter=filter_CoAP_MQTT)
captureSummary = pyshark.LiveCapture(
    interface=networkInterface, bpf_filter=filter_CoAP_MQTT, only_summaries=True)

print("listening on %s" % networkInterface)


class Package(object):
    def __init__(self, size, time):
        self.size = size
        self.time = time


def createPackage(size, time):
    return Package(int(size), float(time))


def getPackageSize(package):
    if (package.size):
        return package.size
    else:
        return 0


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


for captureFullPackage, captureSummary in zip(captureFullPackage.sniff_continuously(), captureSummary.sniff_continuously()):
    counter = counter + 1
    current_package = createPackage(captureSummary.length, captureSummary.time)

    if(counter < 10):
        if(hasattr(captureFullPackage, '_ws.malformed')):
            current_package = createPackage(
                captureFullPackage.tcp.pdu_size, captureSummary.time)

        packages.append(current_package)
    else:
        package_size_avr = calculate_package_size_average(packages)
        package_size = identify_package_size(package_size_avr)
        package_total_time = calculate_total_time(packages)
        final_size = package_size
        packages = []
        counter = 0
        packages.append(current_package)

        # There is package lost
        if(hasattr(captureFullPackage.tcp, 'analysis')):
            if((captureFullPackage.tcp.analysis.flags > package_lost_limit) and (package_size == small or package_size == medium)):
                if(package_size == small and (package_size_avr >= 90 and package_size_avr <= 100)):
                    final_size = medium

                if(package_size == medium and (package_size_avr > 400 and package_size_avr < 500)):
                    final_size = large

        print(best_protocols[final_size])
