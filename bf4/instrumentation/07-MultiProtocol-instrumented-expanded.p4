enum flow_def_set_egress_0__action_type_t {
    discard,
    send_packet
}

struct flow_def_set_egress_0 {
    bool                                 hit;
    bool                                 reach;
    flow_def_set_egress_0__action_type_t action_run;
    @matchKind("exact") 
    bit<1>                               key_set_egress_0_ing_metadata_drop;
}

@controlled() extern flow_def_set_egress_0 query_set_egress_0(@matchKind("exact") in bit<1> set_egress_0_ing_metadata_drop);
extern void end_set_egress_0();
enum flow_def_ipv6_match_0__action_type_t {
    nop_7,
    set_egress_port_3
}

struct flow_def_ipv6_match_0 {
    bool                                 hit;
    bool                                 reach;
    flow_def_ipv6_match_0__action_type_t action_run;
    bit<9>                               set_egress_port_3__egress_port;
    @matchKind("exact") 
    bit<128>                             key_ipv6_match_0_ipv6_dstAddr;
}

@controlled() extern flow_def_ipv6_match_0 query_ipv6_match_0(@matchKind("exact") in bit<128> ipv6_match_0_ipv6_dstAddr);
extern void end_ipv6_match_0();
enum flow_def_ipv4_match_0__action_type_t {
    nop_6,
    set_egress_port,
    NoAction_10
}

struct flow_def_ipv4_match_0 {
    bool                                 hit;
    bool                                 reach;
    flow_def_ipv4_match_0__action_type_t action_run;
    bit<9>                               set_egress_port__egress_port;
    @matchKind("exact") 
    bit<32>                              key_ipv4_match_0_ipv4_dstAddr;
}

@controlled() extern flow_def_ipv4_match_0 query_ipv4_match_0(@matchKind("exact") in bit<32> ipv4_match_0_ipv4_dstAddr);
extern void end_ipv4_match_0();
enum flow_def_icmp_check_0__action_type_t {
    nop,
    _drop,
    NoAction_9
}

struct flow_def_icmp_check_0 {
    bool                                 hit;
    bool                                 reach;
    flow_def_icmp_check_0__action_type_t action_run;
    @matchKind("exact") 
    bit<16>                              key_icmp_check_0_icmp_typeCode;
}

@controlled() extern flow_def_icmp_check_0 query_icmp_check_0(@matchKind("exact") in bit<16> icmp_check_0_icmp_typeCode);
extern void end_icmp_check_0();
enum flow_def_ethertype_match_0__action_type_t {
    l2_packet,
    ipv4_packet,
    ipv6_packet,
    mpls_packet,
    mim_packet,
    NoAction_0
}

struct flow_def_ethertype_match_0 {
    bool                                      hit;
    bool                                      reach;
    flow_def_ethertype_match_0__action_type_t action_run;
    @matchKind("exact") 
    bit<16>                                   key_ethertype_match_0_ethernet_etherType;
}

@controlled() extern flow_def_ethertype_match_0 query_ethertype_match_0(@matchKind("exact") in bit<16> ethertype_match_0_ethernet_etherType);
extern void end_ethertype_match_0();
enum flow_def_udp_check_0__action_type_t {
    nop_10,
    _drop_4,
    NoAction_15
}

struct flow_def_udp_check_0 {
    bool                                hit;
    bool                                reach;
    flow_def_udp_check_0__action_type_t action_run;
    @matchKind("exact") 
    bit<16>                             key_udp_check_0_udp_dstPort;
}

@controlled() extern flow_def_udp_check_0 query_udp_check_0(@matchKind("exact") in bit<16> udp_check_0_udp_dstPort);
extern void end_udp_check_0();
enum flow_def_tcp_check_0__action_type_t {
    nop_9,
    _drop_3,
    NoAction_14
}

struct flow_def_tcp_check_0 {
    bool                                hit;
    bool                                reach;
    flow_def_tcp_check_0__action_type_t action_run;
    @matchKind("exact") 
    bit<16>                             key_tcp_check_0_tcp_dstPort;
}

@controlled() extern flow_def_tcp_check_0 query_tcp_check_0(@matchKind("exact") in bit<16> tcp_check_0_tcp_dstPort);
extern void end_tcp_check_0();
enum flow_def_l2_match_0__action_type_t {
    nop_8,
    set_egress_port_4,
    NoAction_12
}

struct flow_def_l2_match_0 {
    bool                               hit;
    bool                               reach;
    flow_def_l2_match_0__action_type_t action_run;
    bit<9>                             set_egress_port_4__egress_port;
    @matchKind("exact") 
    bit<48>                            key_l2_match_0_ethernet_dstAddr;
}

@controlled() extern flow_def_l2_match_0 query_l2_match_0(@matchKind("exact") in bit<48> l2_match_0_ethernet_dstAddr);
extern void end_l2_match_0();
extern void key_match(in bool condition);
extern void angelic_assert(in bool condition);
extern void bug();

#include <core.p4>

#include <v1model.p4>

struct ingress_metadata_t {
    bit<1> drop;
    bit<9> egress_port;
    bit<4> packet_type;
}

header ethernet_t {
    bit<48> dstAddr;
    bit<48> srcAddr;
    bit<16> etherType;
}

header icmp_t {
    bit<16> typeCode;
    bit<16> hdrChecksum;
}

header ipv4_t {
    bit<4>  version;
    bit<4>  ihl;
    bit<8>  diffserv;
    bit<16> totalLen;
    bit<16> identification;
    bit<3>  flags;
    bit<13> fragOffset;
    bit<8>  ttl;
    bit<8>  protocol;
    bit<16> hdrChecksum;
    bit<32> srcAddr;
    bit<32> dstAddr;
}

header ipv6_t {
    bit<4>   version;
    bit<8>   trafficClass;
    bit<20>  flowLabel;
    bit<16>  payloadLen;
    bit<8>   nextHdr;
    bit<8>   hopLimit;
    bit<128> srcAddr;
    bit<128> dstAddr;
}

header tcp_t {
    bit<16> srcPort;
    bit<16> dstPort;
    bit<32> seqNo;
    bit<32> ackNo;
    bit<4>  dataOffset;
    bit<4>  res;
    bit<8>  flags;
    bit<16> window;
    bit<16> checksum;
    bit<16> urgentPtr;
}

header udp_t {
    bit<16> srcPort;
    bit<16> dstPort;
    bit<16> length_;
    bit<16> checksum;
}

header vlan_tag_t {
    bit<3>  pcp;
    bit<1>  cfi;
    bit<12> vid;
    bit<16> etherType;
}

struct metadata {
    bit<1> _ing_metadata_drop0;
    bit<9> _ing_metadata_egress_port1;
    bit<4> _ing_metadata_packet_type2;
}

struct headers {
    @name(".ethernet") 
    ethernet_t ethernet;
    @name(".icmp") 
    icmp_t     icmp;
    @name(".ipv4") 
    ipv4_t     ipv4;
    @name(".ipv6") 
    ipv6_t     ipv6;
    @name(".tcp") 
    tcp_t      tcp;
    @name(".udp") 
    udp_t      udp;
    @name(".vlan_tag") 
    vlan_tag_t vlan_tag;
}

parser ParserImpl(packet_in packet, out headers hdr, inout metadata meta, inout standard_metadata_t standard_metadata) {
    @name(".parse_icmp") state parse_icmp {
        packet.extract<icmp_t>(hdr.icmp);
        transition accept;
    }
    @name(".parse_ipv4") state parse_ipv4 {
        packet.extract<ipv4_t>(hdr.ipv4);
        transition select(hdr.ipv4.fragOffset, hdr.ipv4.ihl, hdr.ipv4.protocol) {
            (13w0x0 &&& 13w0x0, 4w0x5 &&& 4w0xf, 8w0x1 &&& 8w0xff): parse_icmp;
            (13w0x0 &&& 13w0x0, 4w0x5 &&& 4w0xf, 8w0x6 &&& 8w0xff): parse_tcp;
            (13w0x0 &&& 13w0x0, 4w0x5 &&& 4w0xf, 8w0x11 &&& 8w0xff): parse_udp;
            default: accept;
        }
    }
    @name(".parse_ipv6") state parse_ipv6 {
        packet.extract<ipv6_t>(hdr.ipv6);
        transition select(hdr.ipv6.nextHdr) {
            8w0x1: parse_icmp;
            8w0x6: parse_tcp;
            8w0x11: parse_udp;
            default: accept;
        }
    }
    @name(".parse_tcp") state parse_tcp {
        packet.extract<tcp_t>(hdr.tcp);
        transition accept;
    }
    @name(".parse_udp") state parse_udp {
        packet.extract<udp_t>(hdr.udp);
        transition accept;
    }
    @name(".parse_vlan_tag") state parse_vlan_tag {
        packet.extract<vlan_tag_t>(hdr.vlan_tag);
        transition select(hdr.vlan_tag.etherType) {
            16w0x800: parse_ipv4;
            16w0x86dd: parse_ipv6;
            default: accept;
        }
    }
    @name(".start") state start {
        packet.extract<ethernet_t>(hdr.ethernet);
        transition select(hdr.ethernet.etherType) {
            16w0x8100: parse_vlan_tag;
            16w0x9100: parse_vlan_tag;
            16w0x800: parse_ipv4;
            16w0x86dd: parse_ipv6;
            default: accept;
        }
    }
}

control egress(inout headers hdr, inout metadata meta, inout standard_metadata_t standard_metadata) {
    apply {
    }
}

control ingress(inout headers hdr, inout metadata meta, inout standard_metadata_t standard_metadata) {
    bool __track_egress_spec_0;
    apply {
        __track_egress_spec_0 = false;
        {
            flow_def_ethertype_match_0 ethertype_match;
            ethertype_match = query_ethertype_match_0(hdr.ethernet.etherType);
            if (ethertype_match.hit) {
                key_match(hdr.ethernet.etherType == ethertype_match.key_ethertype_match_0_ethernet_etherType);
                if (!hdr.ethernet.isValid())  {
                    bug();
                } 
            }
            if (ethertype_match.action_run == flow_def_ethertype_match_0__action_type_t.NoAction_0) {
            }
            else  {
                if (ethertype_match.action_run == flow_def_ethertype_match_0__action_type_t.mim_packet) {
                    angelic_assert(true);
                    {
                        meta._ing_metadata_packet_type2 = 4w4;
                    }
                }
                else  {
                    if (ethertype_match.action_run == flow_def_ethertype_match_0__action_type_t.mpls_packet) {
                        angelic_assert(true);
                        {
                            meta._ing_metadata_packet_type2 = 4w3;
                        }
                    }
                    else  {
                        if (ethertype_match.action_run == flow_def_ethertype_match_0__action_type_t.ipv6_packet) {
                            angelic_assert(true);
                            {
                                meta._ing_metadata_packet_type2 = 4w2;
                            }
                        }
                        else  {
                            if (ethertype_match.action_run == flow_def_ethertype_match_0__action_type_t.ipv4_packet) {
                                angelic_assert(true);
                                {
                                    meta._ing_metadata_packet_type2 = 4w1;
                                }
                            }
                            else  {
                                if (ethertype_match.action_run == flow_def_ethertype_match_0__action_type_t.l2_packet) {
                                    angelic_assert(true);
                                    {
                                        meta._ing_metadata_packet_type2 = 4w0;
                                    }
                                }
                                else  {
                                    ;
                                }
                            }
                        }
                    }
                }
            }
            end_ethertype_match_0();
            if (ethertype_match.action_run == flow_def_ethertype_match_0__action_type_t.ipv6_packet) {
                {
                    flow_def_ipv6_match_0 ipv6_match;
                    ipv6_match = query_ipv6_match_0(hdr.ipv6.dstAddr);
                    if (ipv6_match.hit) {
                        key_match(hdr.ipv6.dstAddr == ipv6_match.key_ipv6_match_0_ipv6_dstAddr);
                        if (!hdr.ipv6.isValid())  {
                            bug();
                        } 
                    }
                    if (ipv6_match.action_run == flow_def_ipv6_match_0__action_type_t.set_egress_port_3) {
                        angelic_assert(true);
                        {
                            meta._ing_metadata_egress_port1 = ipv6_match.set_egress_port_3__egress_port;
                        }
                    }
                    else  {
                        if (ipv6_match.action_run == flow_def_ipv6_match_0__action_type_t.nop_7) {
                            angelic_assert(true);
                            {
                            }
                        }
                        else  {
                            ;
                        }
                    }
                    end_ipv6_match_0();
                }
            }
            else  {
                if (ethertype_match.action_run == flow_def_ethertype_match_0__action_type_t.mpls_packet)  {
                    ;
                } 
                else  {
                    if (ethertype_match.action_run == flow_def_ethertype_match_0__action_type_t.ipv4_packet) {
                        {
                            flow_def_ipv4_match_0 ipv4_match;
                            ipv4_match = query_ipv4_match_0(hdr.ipv4.dstAddr);
                            if (ipv4_match.hit) {
                                key_match(hdr.ipv4.dstAddr == ipv4_match.key_ipv4_match_0_ipv4_dstAddr);
                                if (!hdr.ipv4.isValid())  {
                                    bug();
                                } 
                            }
                            if (ipv4_match.action_run == flow_def_ipv4_match_0__action_type_t.NoAction_10) {
                            }
                            else  {
                                if (ipv4_match.action_run == flow_def_ipv4_match_0__action_type_t.set_egress_port) {
                                    angelic_assert(true);
                                    {
                                        meta._ing_metadata_egress_port1 = ipv4_match.set_egress_port__egress_port;
                                    }
                                }
                                else  {
                                    if (ipv4_match.action_run == flow_def_ipv4_match_0__action_type_t.nop_6) {
                                        angelic_assert(true);
                                        {
                                        }
                                    }
                                    else  {
                                        ;
                                    }
                                }
                            }
                            end_ipv4_match_0();
                        }
                    }
                    else {
                        {
                            flow_def_l2_match_0 l2_match;
                            l2_match = query_l2_match_0(hdr.ethernet.dstAddr);
                            if (l2_match.hit) {
                                key_match(hdr.ethernet.dstAddr == l2_match.key_l2_match_0_ethernet_dstAddr);
                                if (!hdr.ethernet.isValid())  {
                                    bug();
                                } 
                            }
                            if (l2_match.action_run == flow_def_l2_match_0__action_type_t.NoAction_12) {
                            }
                            else  {
                                if (l2_match.action_run == flow_def_l2_match_0__action_type_t.set_egress_port_4) {
                                    angelic_assert(true);
                                    {
                                        meta._ing_metadata_egress_port1 = l2_match.set_egress_port_4__egress_port;
                                    }
                                }
                                else  {
                                    if (l2_match.action_run == flow_def_l2_match_0__action_type_t.nop_8) {
                                        angelic_assert(true);
                                        {
                                        }
                                    }
                                    else  {
                                        ;
                                    }
                                }
                            }
                            end_l2_match_0();
                        }
                    }
                }
            }
        }
        if (hdr.tcp.isValid()) {
            flow_def_tcp_check_0 tcp_check;
            tcp_check = query_tcp_check_0(hdr.tcp.dstPort);
            if (tcp_check.hit) {
                key_match(hdr.tcp.dstPort == tcp_check.key_tcp_check_0_tcp_dstPort);
                if (!hdr.tcp.isValid())  {
                    bug();
                } 
            }
            if (tcp_check.action_run == flow_def_tcp_check_0__action_type_t.NoAction_14) {
            }
            else  {
                if (tcp_check.action_run == flow_def_tcp_check_0__action_type_t._drop_3) {
                    angelic_assert(true);
                    {
                        meta._ing_metadata_drop0 = 1w1;
                    }
                }
                else  {
                    if (tcp_check.action_run == flow_def_tcp_check_0__action_type_t.nop_9) {
                        angelic_assert(true);
                        {
                        }
                    }
                    else  {
                        ;
                    }
                }
            }
            end_tcp_check_0();
        }
        else  {
            if (hdr.udp.isValid()) {
                flow_def_udp_check_0 udp_check;
                udp_check = query_udp_check_0(hdr.udp.dstPort);
                if (udp_check.hit) {
                    key_match(hdr.udp.dstPort == udp_check.key_udp_check_0_udp_dstPort);
                    if (!hdr.udp.isValid())  {
                        bug();
                    } 
                }
                if (udp_check.action_run == flow_def_udp_check_0__action_type_t.NoAction_15) {
                }
                else  {
                    if (udp_check.action_run == flow_def_udp_check_0__action_type_t._drop_4) {
                        angelic_assert(true);
                        {
                            meta._ing_metadata_drop0 = 1w1;
                        }
                    }
                    else  {
                        if (udp_check.action_run == flow_def_udp_check_0__action_type_t.nop_10) {
                            angelic_assert(true);
                            {
                            }
                        }
                        else  {
                            ;
                        }
                    }
                }
                end_udp_check_0();
            }
            else  {
                if (hdr.icmp.isValid()) {
                    flow_def_icmp_check_0 icmp_check;
                    icmp_check = query_icmp_check_0(hdr.icmp.typeCode);
                    if (icmp_check.hit) {
                        key_match(hdr.icmp.typeCode == icmp_check.key_icmp_check_0_icmp_typeCode);
                        if (!hdr.icmp.isValid())  {
                            bug();
                        } 
                    }
                    if (icmp_check.action_run == flow_def_icmp_check_0__action_type_t.NoAction_9) {
                    }
                    else  {
                        if (icmp_check.action_run == flow_def_icmp_check_0__action_type_t._drop) {
                            angelic_assert(true);
                            {
                                meta._ing_metadata_drop0 = 1w1;
                            }
                        }
                        else  {
                            if (icmp_check.action_run == flow_def_icmp_check_0__action_type_t.nop) {
                                angelic_assert(true);
                                {
                                }
                            }
                            else  {
                                ;
                            }
                        }
                    }
                    end_icmp_check_0();
                }
            }
        }
        {
            flow_def_set_egress_0 set_egress;
            set_egress = query_set_egress_0(meta._ing_metadata_drop0);
            if (set_egress.hit) {
                key_match(meta._ing_metadata_drop0 == set_egress.key_set_egress_0_ing_metadata_drop);
            }
            if (set_egress.action_run == flow_def_set_egress_0__action_type_t.send_packet) {
                angelic_assert(true);
                {
                    standard_metadata.egress_spec = meta._ing_metadata_egress_port1;
                    __track_egress_spec_0 = true;
                }
            }
            else  {
                if (set_egress.action_run == flow_def_set_egress_0__action_type_t.discard) {
                    angelic_assert(true);
                    {
                        standard_metadata.egress_spec = 9w511;
                        __track_egress_spec_0 = true;
                    }
                }
                else  {
                    ;
                }
            }
            end_set_egress_0();
        }
        if (!__track_egress_spec_0)  {
            bug();
        } 
    }
}

control DeparserImpl(packet_out packet, in headers hdr) {
    apply {
        packet.emit<ethernet_t>(hdr.ethernet);
        packet.emit<vlan_tag_t>(hdr.vlan_tag);
        packet.emit<ipv6_t>(hdr.ipv6);
        packet.emit<ipv4_t>(hdr.ipv4);
        packet.emit<udp_t>(hdr.udp);
        packet.emit<tcp_t>(hdr.tcp);
        packet.emit<icmp_t>(hdr.icmp);
    }
}

control verifyChecksum(inout headers hdr, inout metadata meta) {
    apply {
    }
}

control computeChecksum(inout headers hdr, inout metadata meta) {
    apply {
    }
}

V1Switch<headers, metadata>(ParserImpl(), verifyChecksum(), ingress(), egress(), computeChecksum(), DeparserImpl()) main;

void copy_field_list(in metadata from, inout metadata to, in standard_metadata_t smfrom, inout standard_metadata_t smto, in bit<16> discriminator) {
}
