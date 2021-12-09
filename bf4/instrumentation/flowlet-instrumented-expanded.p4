enum flow_def_forward_0__action_type_t {
    set_dmac,
    _drop_6,
    NoAction_10
}

struct flow_def_forward_0 {
    bool                              hit;
    bool                              reach;
    flow_def_forward_0__action_type_t action_run;
    bit<48>                           set_dmac__dmac;
    @matchKind("exact") 
    bit<32>                           key_forward_0_ingress_metadata_nhop_ipv4;
}

@controlled() extern flow_def_forward_0 query_forward_0(@matchKind("exact") in bit<32> forward_0_ingress_metadata_nhop_ipv4);
extern void end_forward_0();
enum flow_def_flowlet_0__action_type_t {
    lookup_flowlet_map
}

struct flow_def_flowlet_0 {
    bool                              hit;
    bool                              reach;
    flow_def_flowlet_0__action_type_t action_run;
}

@controlled() extern flow_def_flowlet_0 query_flowlet_0();
extern void end_flowlet_0();
enum flow_def_ecmp_nhop_0__action_type_t {
    _drop_5,
    set_nhop
}

struct flow_def_ecmp_nhop_0 {
    bool                                hit;
    bool                                reach;
    flow_def_ecmp_nhop_0__action_type_t action_run;
    bit<32>                             set_nhop__nhop_ipv4;
    bit<9>                              set_nhop__port;
    @matchKind("exact") 
    bit<14>                             key_ecmp_nhop_0_ingress_metadata_ecmp_offset;
}

@controlled() extern flow_def_ecmp_nhop_0 query_ecmp_nhop_0(@matchKind("exact") in bit<14> ecmp_nhop_0_ingress_metadata_ecmp_offset);
extern void end_ecmp_nhop_0();
enum flow_def_new_flowlet_0__action_type_t {
    update_flowlet_id
}

struct flow_def_new_flowlet_0 {
    bool                                  hit;
    bool                                  reach;
    flow_def_new_flowlet_0__action_type_t action_run;
}

@controlled() extern flow_def_new_flowlet_0 query_new_flowlet_0();
extern void end_new_flowlet_0();
enum flow_def_ecmp_group_0__action_type_t {
    _drop_2,
    set_ecmp_select,
    NoAction_1
}

struct flow_def_ecmp_group_0 {
    bool                                 hit;
    bool                                 reach;
    flow_def_ecmp_group_0__action_type_t action_run;
    bit<8>                               set_ecmp_select__ecmp_base;
    bit<8>                               set_ecmp_select__ecmp_count;
    @matchKind("lpm") 
    bit<32>                              key_ecmp_group_0_ipv4_dstAddr__val;
    @matchKind("lpm") 
    bit<32>                              key_ecmp_group_0_ipv4_dstAddr__prefix;
}

@controlled() extern flow_def_ecmp_group_0 query_ecmp_group_0(@matchKind("lpm") in bit<32> ecmp_group_0_ipv4_dstAddr);
extern void end_ecmp_group_0();
enum flow_def_send_frame_0__action_type_t {
    rewrite_mac,
    _drop,
    NoAction_0
}

struct flow_def_send_frame_0 {
    bool                                 hit;
    bool                                 reach;
    flow_def_send_frame_0__action_type_t action_run;
    bit<48>                              rewrite_mac__smac;
    @matchKind("exact") 
    bit<9>                               key_send_frame_0_standard_metadata_egress_port;
}

@controlled() extern flow_def_send_frame_0 query_send_frame_0(@matchKind("exact") in bit<9> send_frame_0_standard_metadata_egress_port);
extern void end_send_frame_0();
extern void key_match(in bool condition);
extern void angelic_assert(in bool condition);
extern void bug();

#include <core.p4>

#include <v1model.p4>

struct ingress_metadata_t {
    bit<32> flow_ipg;
    bit<13> flowlet_map_index;
    bit<16> flowlet_id;
    bit<32> flowlet_lasttime;
    bit<14> ecmp_offset;
    bit<32> nhop_ipv4;
}

struct intrinsic_metadata_t {
    bit<48> ingress_global_timestamp;
    bit<32> lf_field_list;
    bit<16> mcast_grp;
    bit<16> egress_rid;
}

header ethernet_t {
    bit<48> dstAddr;
    bit<48> srcAddr;
    bit<16> etherType;
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

header tcp_t {
    bit<16> srcPort;
    bit<16> dstPort;
    bit<32> seqNo;
    bit<32> ackNo;
    bit<4>  dataOffset;
    bit<3>  res;
    bit<3>  ecn;
    bit<6>  ctrl;
    bit<16> window;
    bit<16> checksum;
    bit<16> urgentPtr;
}

struct metadata {
    bit<32> _ingress_metadata_flow_ipg0;
    bit<13> _ingress_metadata_flowlet_map_index1;
    bit<16> _ingress_metadata_flowlet_id2;
    bit<32> _ingress_metadata_flowlet_lasttime3;
    bit<14> _ingress_metadata_ecmp_offset4;
    bit<32> _ingress_metadata_nhop_ipv45;
    bit<48> _intrinsic_metadata_ingress_global_timestamp6;
    bit<32> _intrinsic_metadata_lf_field_list7;
    bit<16> _intrinsic_metadata_mcast_grp8;
    bit<16> _intrinsic_metadata_egress_rid9;
}

struct headers {
    @name(".ethernet") 
    ethernet_t ethernet;
    @name(".ipv4") 
    ipv4_t     ipv4;
    @name(".tcp") 
    tcp_t      tcp;
}

parser ParserImpl(packet_in packet, out headers hdr, inout metadata meta, inout standard_metadata_t standard_metadata) {
    @name(".parse_ethernet") state parse_ethernet {
        packet.extract<ethernet_t>(hdr.ethernet);
        transition select(hdr.ethernet.etherType) {
            16w0x800: parse_ipv4;
            default: accept;
        }
    }
    @name(".parse_ipv4") state parse_ipv4 {
        packet.extract<ipv4_t>(hdr.ipv4);
        transition select(hdr.ipv4.protocol) {
            8w6: parse_tcp;
            default: accept;
        }
    }
    @name(".parse_tcp") state parse_tcp {
        packet.extract<tcp_t>(hdr.tcp);
        transition accept;
    }
    @name(".start") state start {
        transition parse_ethernet;
    }
}

control egress(inout headers hdr, inout metadata meta, inout standard_metadata_t standard_metadata) {
    apply {
        {
            flow_def_send_frame_0 send_frame;
            send_frame = query_send_frame_0(standard_metadata.egress_port);
            if (send_frame.hit) {
                key_match(standard_metadata.egress_port == send_frame.key_send_frame_0_standard_metadata_egress_port);
            }
            if (send_frame.action_run == flow_def_send_frame_0__action_type_t.NoAction_0) {
            }
            else  {
                if (send_frame.action_run == flow_def_send_frame_0__action_type_t._drop) {
                    angelic_assert(true);
                    {
                        standard_metadata.egress_spec = 9w511;
                    }
                }
                else  {
                    if (send_frame.action_run == flow_def_send_frame_0__action_type_t.rewrite_mac) {
                        angelic_assert(true);
                        {
                            if (hdr.ethernet.isValid())  {
                                hdr.ethernet.srcAddr = send_frame.rewrite_mac__smac;
                            } 
                            else  {
                                bug();
                            }
                        }
                    }
                    else  {
                        ;
                    }
                }
            }
            end_send_frame_0();
        }
    }
}

struct tuple_0 {
    bit<32> field;
    bit<32> field_0;
    bit<8>  field_1;
    bit<16> field_2;
    bit<16> field_3;
    bit<16> field_4;
}

struct tuple_1 {
    bit<32> field_5;
    bit<32> field_6;
    bit<8>  field_7;
    bit<16> field_8;
    bit<16> field_9;
}

control ingress(inout headers hdr, inout metadata meta, inout standard_metadata_t standard_metadata) {
    bool __track_egress_spec_0;
    @name("ingress.flowlet_id") register<bit<16>>(32w8192) flowlet_id_0;
    @name("ingress.flowlet_lasttime") register<bit<32>>(32w8192) flowlet_lasttime_0;
    apply {
        __track_egress_spec_0 = false;
        {
            flow_def_flowlet_0 flowlet;
            flowlet = query_flowlet_0();
            ;
            if (flowlet.action_run == flow_def_flowlet_0__action_type_t.lookup_flowlet_map) {
                angelic_assert(true);
                {
                    hash<bit<13>, bit<13>, tuple_1, bit<26>>(meta._ingress_metadata_flowlet_map_index1, HashAlgorithm.crc16, 13w0, tuple_1 {field_5 = hdr.ipv4.srcAddr,field_6 = hdr.ipv4.dstAddr,field_7 = hdr.ipv4.protocol,field_8 = hdr.tcp.srcPort,field_9 = hdr.tcp.dstPort}, 26w13);
                    if ((bit<32>)meta._ingress_metadata_flowlet_map_index1 >= 32w8192)  {
                        bug();
                    } 
                    flowlet_id_0.read(meta._ingress_metadata_flowlet_id2, (bit<32>)meta._ingress_metadata_flowlet_map_index1);
                    if ((bit<32>)meta._ingress_metadata_flowlet_map_index1 >= 32w8192)  {
                        bug();
                    } 
                    flowlet_lasttime_0.read(meta._ingress_metadata_flowlet_lasttime3, (bit<32>)meta._ingress_metadata_flowlet_map_index1);
                    meta._ingress_metadata_flow_ipg0 = (bit<32>)meta._intrinsic_metadata_ingress_global_timestamp6 - meta._ingress_metadata_flowlet_lasttime3;
                    if ((bit<32>)meta._ingress_metadata_flowlet_map_index1 >= 32w8192)  {
                        bug();
                    } 
                    flowlet_lasttime_0.write((bit<32>)meta._ingress_metadata_flowlet_map_index1, (bit<32>)meta._intrinsic_metadata_ingress_global_timestamp6);
                }
            }
            else  {
                ;
            }
            end_flowlet_0();
        }
        if (meta._ingress_metadata_flow_ipg0 > 32w50000) {
            flow_def_new_flowlet_0 new_flowlet;
            new_flowlet = query_new_flowlet_0();
            ;
            if (new_flowlet.action_run == flow_def_new_flowlet_0__action_type_t.update_flowlet_id) {
                angelic_assert(true);
                {
                    meta._ingress_metadata_flowlet_id2 = meta._ingress_metadata_flowlet_id2 + 16w1;
                    if ((bit<32>)meta._ingress_metadata_flowlet_map_index1 >= 32w8192)  {
                        bug();
                    } 
                    flowlet_id_0.write((bit<32>)meta._ingress_metadata_flowlet_map_index1, meta._ingress_metadata_flowlet_id2);
                }
            }
            else  {
                ;
            }
            end_new_flowlet_0();
        }
        {
            flow_def_ecmp_group_0 ecmp_group;
            ecmp_group = query_ecmp_group_0(hdr.ipv4.dstAddr);
            if (ecmp_group.hit) {
                key_match(hdr.ipv4.dstAddr & (32w1 << ecmp_group.key_ecmp_group_0_ipv4_dstAddr__prefix) - 32w1 == ecmp_group.key_ecmp_group_0_ipv4_dstAddr__val & (32w1 << ecmp_group.key_ecmp_group_0_ipv4_dstAddr__prefix) - 32w1);
                if (!(hdr.ipv4.isValid() || (32w1 << ecmp_group.key_ecmp_group_0_ipv4_dstAddr__prefix) - 32w1 == 32w0))  {
                    bug();
                } 
            }
            if (ecmp_group.action_run == flow_def_ecmp_group_0__action_type_t.NoAction_1) {
            }
            else  {
                if (ecmp_group.action_run == flow_def_ecmp_group_0__action_type_t.set_ecmp_select) {
                    angelic_assert(true);
                    {
                        hash<bit<14>, bit<10>, tuple_0, bit<20>>(meta._ingress_metadata_ecmp_offset4, HashAlgorithm.crc16, (bit<10>)ecmp_group.set_ecmp_select__ecmp_base, tuple_0 {field = hdr.ipv4.srcAddr,field_0 = hdr.ipv4.dstAddr,field_1 = hdr.ipv4.protocol,field_2 = hdr.tcp.srcPort,field_3 = hdr.tcp.dstPort,field_4 = meta._ingress_metadata_flowlet_id2}, (bit<20>)ecmp_group.set_ecmp_select__ecmp_count);
                    }
                }
                else  {
                    if (ecmp_group.action_run == flow_def_ecmp_group_0__action_type_t._drop_2) {
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
            }
            end_ecmp_group_0();
        }
        {
            flow_def_ecmp_nhop_0 ecmp_nhop;
            ecmp_nhop = query_ecmp_nhop_0(meta._ingress_metadata_ecmp_offset4);
            if (ecmp_nhop.hit) {
                key_match(meta._ingress_metadata_ecmp_offset4 == ecmp_nhop.key_ecmp_nhop_0_ingress_metadata_ecmp_offset);
            }
            if (ecmp_nhop.action_run == flow_def_ecmp_nhop_0__action_type_t.set_nhop) {
                angelic_assert(true);
                {
                    meta._ingress_metadata_nhop_ipv45 = ecmp_nhop.set_nhop__nhop_ipv4;
                    standard_metadata.egress_spec = ecmp_nhop.set_nhop__port;
                    __track_egress_spec_0 = true;
                    if (hdr.ipv4.isValid() && hdr.ipv4.isValid())  {
                        hdr.ipv4.ttl = hdr.ipv4.ttl + 8w255;
                    } 
                    else  {
                        bug();
                    }
                }
            }
            else  {
                if (ecmp_nhop.action_run == flow_def_ecmp_nhop_0__action_type_t._drop_5) {
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
            end_ecmp_nhop_0();
        }
        {
            flow_def_forward_0 forward;
            forward = query_forward_0(meta._ingress_metadata_nhop_ipv45);
            if (forward.hit) {
                key_match(meta._ingress_metadata_nhop_ipv45 == forward.key_forward_0_ingress_metadata_nhop_ipv4);
            }
            if (forward.action_run == flow_def_forward_0__action_type_t.NoAction_10) {
            }
            else  {
                if (forward.action_run == flow_def_forward_0__action_type_t._drop_6) {
                    angelic_assert(true);
                    {
                        standard_metadata.egress_spec = 9w511;
                        __track_egress_spec_0 = true;
                    }
                }
                else  {
                    if (forward.action_run == flow_def_forward_0__action_type_t.set_dmac) {
                        angelic_assert(true);
                        {
                            if (hdr.ethernet.isValid())  {
                                hdr.ethernet.dstAddr = forward.set_dmac__dmac;
                            } 
                            else  {
                                bug();
                            }
                        }
                    }
                    else  {
                        ;
                    }
                }
            }
            end_forward_0();
        }
        if (!__track_egress_spec_0)  {
            bug();
        } 
    }
}

control DeparserImpl(packet_out packet, in headers hdr) {
    apply {
        packet.emit<ethernet_t>(hdr.ethernet);
        packet.emit<ipv4_t>(hdr.ipv4);
        packet.emit<tcp_t>(hdr.tcp);
    }
}

struct tuple_2 {
    bit<4>  field_10;
    bit<4>  field_11;
    bit<8>  field_12;
    bit<16> field_13;
    bit<16> field_14;
    bit<3>  field_15;
    bit<13> field_16;
    bit<8>  field_17;
    bit<8>  field_18;
    bit<32> field_19;
    bit<32> field_20;
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
