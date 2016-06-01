"""
An OpenFlow 1.0 Science DMZ Controller
"""

import threading
from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import MAIN_DISPATCHER
from ryu.controller.handler import set_ev_cls
from ryu.ofproto import ofproto_v1_0
from ryu.lib.mac import haddr_to_bin
from ryu.lib.ip import ipv4_to_bin
from ryu.lib.packet import packet
from ryu.lib.packet import ethernet
from ryu.lib.packet import ether_types
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

    def add_flow(self, in_port, nw_src, tp_src, nw_dst, tp_dst, actions):
        ofproto = self.datapath.ofproto

        match = self.datapath.ofproto_parser.OFPMatch(
            in_port=in_port, nw_src=nw_src, tp_src=tp_src, nw_dst=nw_dst, tp_dst=tp_dst)

        mod = self.datapath.ofproto_parser.OFPFlowMod(
            datapath=self.datapath, match=match, cookie=0,
            command=ofproto.OFPFC_ADD, idle_timeout=10, hard_timeout=0,
            priority=ofproto.OFP_DEFAULT_PRIORITY,
            flags=ofproto.OFPFF_SEND_FLOW_REM, actions=actions)
        self.datapath.send_msg(mod)

    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def _packet_in_handler(self, ev):
        msg = ev.msg
        if self.datapath is None:
            self.datapath = msg.datapath

        ofproto = self.datapath.ofproto

        pkt = packet.Packet(msg.data)
        eth = pkt.get_protocol(ethernet.ethernet)

        if eth.ethertype == ether_types.ETH_TYPE_LLDP:
            # ignore lldp packet
            return

        ipv4_layer = pkt.get_protocol(ipv4.ipv4)
        transport_layer = pkt.get_protocol(udp.udp)

        if not transport_layer:
            transport_layer = pkt.get_protocol(tcp.tcp)

        if msg.in_port != controller.SECURITY_DEVICE_SWITCH_PORT:
            out_port = controller.SECURITY_DEVICE_SWITCH_PORT
            self.logger.info("Forwarding to DPI.")
        elif eth.dst in self.mac_to_port:
            #this could be a security concern. -RTH 6/1
            self.mac_to_port[eth.src] = msg.in_port
            out_port = self.mac_to_port[eth.dst]
            self.logger.info("Received from DPI.")
        else:
            self.mac_to_port[eth.src] = msg.in_port
            out_port = ofproto.OFPP_FLOOD
            self.logger.info("Received from DPI, flooding.")

        actions = [self.datapath.ofproto_parser.OFPActionOutput(out_port)]

        # install a flow to avoid packet_in next time
        if out_port != ofproto.OFPP_FLOOD and ipv4_layer and transport_layer:
            self.logger.info("add flow %s %s %s:%i -> %s:%i", dpid, msg.in_port, ipv4_layer.src,
                             transport_layer.src_port, ipv4_layer.dst, transport_layer.dst_port)
            self.add_flow(msg.in_port, ipv4_layer.src, transport_layer.src_port,
                          ipv4_layer.dst, transport_layer.dst_port, actions)

        data = None
        if msg.buffer_id == ofproto.OFP_NO_BUFFER:
            data = msg.data

        out = self.datapath.ofproto_parser.OFPPacketOut(
            datapath=self.datapath, buffer_id=msg.buffer_id, in_port=msg.in_port,
            actions=actions, data=data)
        self.datapath.send_msg(out)

    @set_ev_cls(ofp_event.EventOFPFlowStatsReply, MAIN_DISPATCHER)
    def _flow_stats_handler(self, ev):
        msg = ev.msg
        self.logger.info("Flow stats reply")
