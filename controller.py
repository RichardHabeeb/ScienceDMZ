"""
An OpenFlow 1.0 Science DMZ Controller
"""

import threading
import flow
from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import MAIN_DISPATCHER
from ryu.controller.handler import set_ev_cls
from ryu.ofproto import ofproto_v1_0
from ryu.lib.ip import ipv4_to_bin
from ryu.lib.packet import packet
from ryu.lib.packet import ethernet
from ryu.lib.packet import ether_types
from ryu.lib.packet import in_proto
from ryu.lib.packet import ipv4
from ryu.lib.packet import tcp
from ryu.lib.packet import udp


class controller(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_0.OFP_VERSION]
    SECURITY_DEVICE_SWITCH_PORT = 3

    def __init__(self, *args, **kwargs):
        super(controller, self).__init__(*args, **kwargs)
        self.mac_to_port = {}
        self.datapath = None
        self.untrusted_flows = []
        self.dmz_flows = []
        self.get_flow_statistics()

    def get_flow_statistics(self):
        threading.Timer(1.0, self.get_flow_statistics).start()

        if self.datapath is None:
            return

        match = self.datapath.ofproto_parser.OFPMatch(self.datapath.ofproto.OFPFW_ALL, 0, 0, 0,
                                                     0, 0, 0, 0, 0, 0, 0, 0, 0)
        stats = self.datapath.ofproto_parser.OFPFlowStatsRequest(self.datapath, 0, match,
                                                                0xff, self.datapath.ofproto.OFPP_NONE)
        self.datapath.send_msg(stats)

    def add_flow(self, in_port, nw_src, tp_src, nw_dst, tp_dst, nw_proto, actions):
        ofp = self.datapath.ofproto

        match = self.datapath.ofproto_parser.OFPMatch(
            dl_type=ether_types.ETH_TYPE_IP,
            nw_proto=nw_proto,
            in_port=in_port,
            nw_src=nw_src,
            tp_src=int(tp_src),
            nw_dst=nw_dst,
            tp_dst=int(tp_dst))

        f = Flow(match)
        self.untrusted_flows.append(f)
        self.logger.info("add flow %i %i:%i -> %i:%i Wildcard:%s", match.in_port, match.nw_src, match.tp_src, match.nw_dst, match.tp_dst, hex(match.wildcards))
        self.datapath.send_msg(f.get_flow_table_mod_msg(self.datapath, actions))

    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def _packet_in_handler(self, ev):
        msg = ev.msg
        pkt = packet.Packet(msg.data)
        eth = pkt.get_protocol(ethernet.ethernet)

        if eth.ethertype == ether_types.ETH_TYPE_LLDP:
            # ignore lldp packet
            return

        if self.datapath is None:
            self.datapath = msg.datapath

        if self.datapath != msg.datapath:
            elf.logger.info("Different datapath.")

        ofp = self.datapath.ofproto
        ipv4_layer = pkt.get_protocol(ipv4.ipv4)
        transport_layer = pkt.get_protocol(udp.udp)
        nw_proto = in_proto.IPPROTO_UDP

        if not transport_layer:
            transport_layer = pkt.get_protocol(tcp.tcp)
            nw_proto = in_proto.IPPROTO_TCP

        out_port = ofp.OFPP_FLOOD
        if msg.in_port != controller.SECURITY_DEVICE_SWITCH_PORT:
            # this could be a security concern. -RTH 6/1
            self.mac_to_port[eth.src] = msg.in_port
            out_port = controller.SECURITY_DEVICE_SWITCH_PORT
        elif eth.dst in self.mac_to_port:
            out_port = self.mac_to_port[eth.dst]

        if out_port == msg.in_port:
            self.logger.info("Dropping reflected packet.")
            return

        actions = [self.datapath.ofproto_parser.OFPActionOutput(out_port)]

        # install a flow to avoid packet_in next time
        if out_port != ofp.OFPP_FLOOD and ipv4_layer and transport_layer:
            self.add_flow(msg.in_port, ipv4_layer.src, transport_layer.src_port,
                          ipv4_layer.dst, transport_layer.dst_port, nw_proto, actions)

        data = None
        if msg.buffer_id == ofp.OFP_NO_BUFFER:
            data = msg.data

        out = self.datapath.ofproto_parser.OFPPacketOut(
            datapath=self.datapath, buffer_id=msg.buffer_id, in_port=msg.in_port,
            actions=actions, data=data)
        self.datapath.send_msg(out)

    @set_ev_cls(ofp_event.EventOFPFlowStatsReply, MAIN_DISPATCHER)
    def _flow_stats_handler(self, ev):
        msg = ev.msg
        self.logger.info("Flow stats reply")

        flows = []
        for stat in msg.body:
            m = stat.match
            if 'nw_src' in m:
                self.logger.info("size: %i ip: %s", stat.byte_count, m['nw_src'])

    @set_ev_cls(ofp_event.EventOFPErrorMsg, MAIN_DISPATCHER)
    def _error_handler(self, ev):
        msg = ev.msg
        ofp = self.datapath.ofproto
        self.logger.info(
            "EventOFPErrorMsg received.\n"
            "version=%s, msg_type=%s, msg_len=%s, xid=%s\n"
            " `-- msg_type: %s\n"
            "OFPErrorMsg(type=%s, code=%s)\n"
            " |-- type: %s\n"
            " |-- code: %s",
            hex(msg.version), hex(msg.msg_type), hex(msg.msg_len),
            hex(msg.xid), ofp.ofp_msg_type_to_str(msg.msg_type),
            hex(msg.type), hex(msg.code),
            ofp.ofp_error_type_to_str(msg.type),
            ofp.ofp_error_code_to_str(msg.type, msg.code))
