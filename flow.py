

class flow(object):
    RUNNING_AVERAGE_WINDOW = 1
    FLOW_STATS_INTERVAL_SECS = 1

    def __init__(self, match=None, cookie=0):
        self.network_layer_src = None
        self.network_layer_dst = None
        self.transport_layer_src = None
        self.transport_layer_dst = None
        self.hardware_port = None
        self.match = match
        self.sample_timeout = 0
        self.cookie = cookie
        if(match is not None and 'nw_src'in match and 'nw_dst' in match and 'tp_src' in match and 'tp_dst' in match and 'in_port' in match):
            self.network_layer_src = match['nw_src']
            self.network_layer_dst = match['nw_dst']
            self.transport_layer_src = match['tp_src']
            self.transport_layer_dst = match['tp_dst']
            self.hardware_port = match['in_port']

        self.bit_rates = [0] * flow.RUNNING_AVERAGE_WINDOW
        self.running_rate_sum = 0
        self.total_bytes = 0

    def __eq__(self, other):
        if other is None:
            return False
        return \
            self.network_layer_src == other.network_layer_src and \
            self.network_layer_dst == other.network_layer_dst and \
            self.tranport_layer_src == other.tranport_layer_src and \
            self.tranport_layer_dst == other.tranport_layer_dst and \
            self.hardware_port == other.hardware_port

    def get_flow_table_mod_msg(self, datapath, actions):
        return datapath.ofproto_parser.OFPFlowMod(
            datapath=datapath,
            match=self.match,
            cookie=self.cookie,
            command=datapath.ofproto.OFPFC_ADD,
            idle_timeout=10,
            hard_timeout=800,
            priority=datapath.ofproto.OFP_DEFAULT_PRIORITY,
            flags=datapath.ofproto.OFPFF_SEND_FLOW_REM,
            actions=actions)

    def get_flow_table_remove_msg(self, datapath):
        return datapath.ofproto_parser.OFPFlowMod(
            match=self.match,
            #cookie=self.cookie,
            command=datapath.ofproto.OFPFC_DELETE)

    def get_average_rate(self):
        return self.running_rate_sum / flow.RUNNING_AVERAGE_WINDOW

    def add_rate(self, new_rate):
        self.running_rate_sum += new_rate - self.bit_rates.pop(0)
        self.bit_rates.append(new_rate)

    def update_total_bytes_transferred(self, new_total):
        transmission_rate = 8 * \
            (new_total - self.total_bytes) / flow.FLOW_STATS_INTERVAL_SECS
        self.total_bytes = new_total
        self.add_rate(transmission_rate)
