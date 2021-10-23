# NetworkReader
Parse packages in real time from network using Tshark[Wireshark] and save in influxDB(time series DB)
There are two differents interfaces to extract data from network. Choose the best way for you!

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
    ```
        python3.8 ./parseNetworkPython.py
    ```
 * Install [pyshark](https://github.com/KimiNewt/pyshark) and follow the installation requirements based on your operation system.
 * Use at least Python 3.8 (pyshark requirement), but if you're dealing with python version under python3.7 use pyshark-legacy  

 * Install [InfluxDB](https://www.influxdata.co).

 * Install [CoAPthon3](https://github.com/Tanganelli/CoAPthon3).
