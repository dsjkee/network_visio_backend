class Working_service:
    is_active = 0
    input_traffic = 0
    port = 0

    def __init__(self, port):
        self.port = port

class Working_host:
    is_active = 0
    ip_addr = ""
    w_services = []
    input_traffic = 0

    def __init__(self, service_count, ports, address):
        i = 0
        self.ip_addr = address
        while(i != service_count - 1):
            f = Working_service(ports[i])
            self.w_services.append(f)
            i += 1
