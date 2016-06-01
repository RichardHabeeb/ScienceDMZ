# Copyright (C) 2011 Nippon Telegraph and Telephone Corporation.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#    http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or
# implied.
# See the License for the specific language governing permissions and
# limitations under the License.

"""
An OpenFlow 1.0 L2 learning switch implementation.
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


class SimpleSwitch(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_0.OFP_VERSION]

    def __init__(self, *args, **kwargs):
        super(SimpleSwitch, self).__init__(*args, **kwargs)
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

        dst = eth.dst
        src = eth.src

        dpid = self.datapath.id
        self.mac_to_port.setdefault(dpid, {})

        # learn a mac address to avoid FLOOD next time.
        self.mac_to_port[dpid][src] = msg.in_port

        if dst in self.mac_to_port[dpid]:
            out_port = self.mac_to_port[dpid][dst]
        else:
            out_port = ofproto.OFPP_FLOOD

        actions = [self.datapath.ofproto_parser.OFPActionOutput(out_port)]

        # install a flow to avoid packet_in next time
        if out_port != ofproto.OFPP_FLOOD and ipv4_layer and transport_layer:
            self.logger.info("add flow %s %s %s:%i %s:%i", dpid, msg.in_port, ipv4_layer.src, transport_layer.src_port, ipv4_layer.dst, transport_layer.dst_port)
            self.add_flow(msg.in_port, ipv4_layer.src, transport_layer.src_port, ipv4_layer.dst, transport_layer.dst_port, actions)

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


    @set_ev_cls(ofp_event.EventOFPPortStatus, MAIN_DISPATCHER)
    def _port_status_handler(self, ev):
        msg = ev.msg
        reason = msg.reason
        port_no = msg.desc.port_no

        ofproto = msg.datapath.ofproto
        if reason == ofproto.OFPPR_ADD:
            self.logger.info("port added %s", port_no)
        elif reason == ofproto.OFPPR_DELETE:
            self.logger.info("port deleted %s", port_no)
        elif reason == ofproto.OFPPR_MODIFY:
            self.logger.info("port modified %s", port_no)
        else:
            self.logger.info("Illeagal port state %s %s", port_no, reason)
