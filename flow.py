

class flow(object):
    RUNNING_AVERAGE_WINDOW = 1
    FLOW_STATS_INTERVAL_SECS = 5

    def __init__(self, match=None, cookie=0, dl_dst=None):
        self.match = match
        self.sample_timeout = 0
        self.cookie = cookie
        self.bit_rates = [0] * flow.RUNNING_AVERAGE_WINDOW
        self.running_rate_sum = 0
        self.total_bytes = 0
        self.dl_dst = dl_dst

    def get_flow_table_mod_msg(self, datapath, actions, command):
        return datapath.ofproto_parser.OFPFlowMod(
            datapath=datapath,
            match=self.match,
            cookie=self.cookie,
            command=command,
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
