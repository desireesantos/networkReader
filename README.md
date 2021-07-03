# NetworkReader
Parse packages in real time from network using Tshark[Wireshark]

 There are two differents way to extract data from network.

 #### Shell
  Shell script using tshark library
    ```shell
        bash ./parseNetworkShell
    ```
###### Requirement
 * Install [Wireshard](https://www.wireshark.org/#download) and don't forget to enable the tshark.  
 Tshart is a command-line network protocol analyzer.

 #### Python
   Python script using pyshark
    ```python
        python3.8 ./parseNetworkPython.py
    ```
 * Install [pyshark](https://github.com/KimiNewt/pyshark) and follow the installation requirements based on your operation system.
 * Use Python 3.8 (pyshark requirement)  

 * Install [InfluxDB](https://www.influxdata.com/).
