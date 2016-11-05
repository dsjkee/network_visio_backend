The main purpose of this app - is select packets which consist of some filter parametrs
and translete information about this packets to GUI.
Filter parametrs are set by programm running.
Now, it parametrs is:
host_ip and service_port.
For runnig this app you must using only python 2.7.
Give to app parameters in view:
<host_count_N> <ip_host_1> <ip_host_2> <ip_host_N> <service_count_M> <port_service_1> <port_service_2> <port_service_M>
For example:

python2.7 ./backend_kernel.py 2 192.168.1.1 192.168.1.2 3 80 22 23
