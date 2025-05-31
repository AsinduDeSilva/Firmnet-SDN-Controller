from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import MAIN_DISPATCHER, CONFIG_DISPATCHER, set_ev_cls
from ryu.ofproto import ofproto_v1_3
from ryu.lib.packet import packet, ethernet, ipv4
from ryu.app.wsgi import ControllerBase, WSGIApplication, route
from webob import Response
import json

REST_API = '/flow'
controller_instance_name = 'flow_rest_controller'

class SimpleFlowController(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]
    _CONTEXTS = {'wsgi': WSGIApplication}

    def __init__(self, *args, **kwargs):
        super(SimpleFlowController, self).__init__(*args, **kwargs)
        wsgi = kwargs['wsgi']
        wsgi.register(RestFlowAPI, {controller_instance_name: self})
        self.datapaths = {}

    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def switch_features_handler(self, ev):
        datapath = ev.msg.datapath
        self.datapaths[datapath.id] = datapath
        self.logger.info("Switch connected: %s", datapath.id)
        
        self.add_arp_flow(datapath)

    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def _packet_in_handler(self, ev):
        return None

    def add_flow(self, datapath, src_ip, dst_ip, priority=100):
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        match = parser.OFPMatch(
            eth_type=0x0800,  # IPv4
            ipv4_src=src_ip,
            ipv4_dst=dst_ip
        )
        
        actions = [parser.OFPActionOutput(ofproto.OFPP_NORMAL)]
        inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS, actions)]
        
        mod = parser.OFPFlowMod(datapath=datapath, priority=priority, match=match, instructions=inst)
        datapath.send_msg(mod)
        self.logger.info("Flow added: %s -> %s", src_ip, dst_ip)

    def delete_flow(self, datapath, src_ip, dst_ip):
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        match = parser.OFPMatch(eth_type=0x0800, ipv4_src=src_ip, ipv4_dst=dst_ip)
        mod = parser.OFPFlowMod(datapath=datapath,
                                command=ofproto.OFPFC_DELETE,
                                out_port=ofproto.OFPP_ANY,
                                out_group=ofproto.OFPG_ANY,
                                match=match)
        datapath.send_msg(mod)
        self.logger.info("Flow deleted: %s -> %s", src_ip, dst_ip)
    
    
    def add_arp_flow(self, datapath):
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        match = parser.OFPMatch(eth_type=0x0806)  # ARP
        actions = [parser.OFPActionOutput(ofproto.OFPP_FLOOD)]
        inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS, actions)]
        mod = parser.OFPFlowMod(datapath=datapath, priority=1, match=match, instructions=inst)
        datapath.send_msg(mod)
        self.logger.info("ARP flow added")



class RestFlowAPI(ControllerBase):
    def __init__(self, req, link, data, **config):
        super(RestFlowAPI, self).__init__(req, link, data, **config)
        self.controller = data[controller_instance_name]

    @route('add_flow', REST_API + '/add', methods=['POST'])
    def add_flow(self, req, **kwargs):
        try:
            try:
                content = req.json
            except ValueError:
                return Response(status=400, content_type='application/json', charset='utf-8',
                                text=json.dumps({'error': 'Invalid JSON'}))

            dpid = int(content.get('dpid'))
            src_ip = content.get('src_ip')
            dst_ip = content.get('dst_ip')

            datapath = self.controller.datapaths.get(dpid)
            if datapath:
                self.controller.add_flow(datapath, src_ip, dst_ip)
                return Response(content_type='application/json', charset='utf-8',
                                text=json.dumps({'status': 'flow added'}))
            else:
                return Response(status=404, content_type='application/json', charset='utf-8',
                                text=json.dumps({'error': 'Datapath not found'}))
        except Exception as e:
            return Response(status=500, content_type='application/json', charset='utf-8',
                            text=json.dumps({'error': str(e)}))

    @route('delete_flow', REST_API + '/delete', methods=['POST'])
    def delete_flow(self, req, **kwargs):
        try:
            try:
                content = req.json
            except ValueError:
                return Response(status=400, content_type='application/json', charset='utf-8',
                                text=json.dumps({'error': 'Invalid JSON'}))

            dpid = int(content.get('dpid'))
            src_ip = content.get('src_ip')
            dst_ip = content.get('dst_ip')

            datapath = self.controller.datapaths.get(dpid)
            if datapath:
                self.controller.delete_flow(datapath, src_ip, dst_ip)
                return Response(content_type='application/json', charset='utf-8',
                                text=json.dumps({'status': 'flow deleted'}))
            else:
                return Response(status=404, content_type='application/json', charset='utf-8',
                                text=json.dumps({'error': 'Datapath not found'}))
        except Exception as e:
            return Response(status=500, content_type='application/json', charset='utf-8',
                            text=json.dumps({'error': str(e)}))

