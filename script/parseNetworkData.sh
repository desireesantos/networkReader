#!/bin/bash

index=0

# Create directories to store files
mkdir pcapFiles
mkdir svcFiles

# Filter and save UDP and COAP package from network
tshark -i 1  -f "dst port 5683 and ip dst <ADD DESTINATION IP>" -b filesize:1 -a files:2 -w ./pcapFiles/network_data.pcap

# Convert .pcap to .csv file
for filename in ./pcapFiles/*.pcap; do
    tshark -r "$filename"  -T fields -E separator=, -e ip.src -e ip.dst -e _ws.col.Protocol -e coap.payload_length  -e _ws.col.Info >  "./svcFiles/extracted_${index}.svc"
    index=$(( index + 1 ))
done
