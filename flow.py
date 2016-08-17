

class flow(object):
    RUNNING_AVERAGE_WINDOW = 1
    FLOW_STATS_INTERVAL_SECS = 2

    def __init__(self, match=None, cookie=0, dl_dst=None):
        self.match = match
        self.sample_timeout = 0
        self.cookie = cookie
        self.bit_rates = [0] * flow.RUNNING_AVERAGE_WINDOW
        self.running_rate_sum = 0
        self.total_bytes = 0
        self.dl_dst = dl_dst
        self.score = 0

    def __eq__(self, other):
        return self.match['nw_src'] == other.match['nw_src'] and self.match['nw_dst'] == other.match['nw_dst'] and self.match['tp_src'] == other.match['tp_src'] and self.match['tp_dst'] == other.match['tp_dst'] and self.match['in_port'] == other.match['in_port']

    def compare_l3(self, other):
        return self.match['nw_src'] == other.match['nw_src'] and self.match['nw_dst'] == other.match['nw_dst'] and self.match['tp_src'] == other.match['tp_src'] and self.match['tp_dst'] == other.match['tp_dst']

    def __str__(self):
        return str((self.match['nw_src'], self.match['tp_src'], self.match['nw_dst'], self.match['tp_dst'], self.match['in_port'], self.cookie, self.score, self.get_average_rate()/1000/1000))

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
            # cookie=self.cookie,
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
