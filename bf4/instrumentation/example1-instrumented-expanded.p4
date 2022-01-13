enum flow_def_t2_0__action_type_t {
    validate_H2,
    _drop_7,
    NoAction_9
}

struct flow_def_t2_0 {
    bool                         hit;
    bool                         reach;
    flow_def_t2_0__action_type_t action_run;
    @matchKind("exact") 
    bit<32>                      key_t2_0_hdr_ipv4_dstAddr;
}

@controlled() extern flow_def_t2_0 query_t2_0(@matchKind("exact") in bit<32> t2_0_hdr_ipv4_dstAddr);
extern void end_t2_0();
enum flow_def_t1_0__action_type_t {
    validate_H1,
    _drop_2,
    NoAction_1
}

struct flow_def_t1_0 {
    bool                         hit;
    bool                         reach;
    flow_def_t1_0__action_type_t action_run;
    @matchKind("exact") 
    bit<32>                      key_t1_0_hdr_ipv4_srcAddr;
}

@controlled() extern flow_def_t1_0 query_t1_0(@matchKind("exact") in bit<32> t1_0_hdr_ipv4_srcAddr);
extern void end_t1_0();
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
enum flow_def_ipv4_lpm_0__action_type_t {
    set_nhop,
    _drop_10,
    NoAction_13
}

struct flow_def_ipv4_lpm_0 {
    bool                               hit;
    bool                               reach;
    flow_def_ipv4_lpm_0__action_type_t action_run;
    bit<32>                            set_nhop__nhop_ipv4;
    bit<9>                             set_nhop__port;
    @matchKind("lpm") 
    bit<32>                            key_ipv4_lpm_0_hdr_ipv4_dstAddr__val;
    @matchKind("lpm") 
    bit<32>                            key_ipv4_lpm_0_hdr_ipv4_dstAddr__prefix;
}

@controlled() extern flow_def_ipv4_lpm_0 query_ipv4_lpm_0(@matchKind("lpm") in bit<32> ipv4_lpm_0_hdr_ipv4_dstAddr);
extern void end_ipv4_lpm_0();
enum flow_def_forward_0__action_type_t {
    set_dmac,
    _drop_9,
    NoAction_12
}

struct flow_def_forward_0 {
    bool                              hit;
    bool                              reach;
    flow_def_forward_0__action_type_t action_run;
    bit<48>                           set_dmac__dmac;
    @matchKind("exact") 
    bit<32>                           key_forward_0_meta_custom_metadata_nhop_ipv4;
}

@controlled() extern flow_def_forward_0 query_forward_0(@matchKind("exact") in bit<32> forward_0_meta_custom_metadata_nhop_ipv4);
extern void end_forward_0();
enum flow_def_count_table_0__action_type_t {
    count_action,
    _drop_8,
    NoAction_11
}

struct flow_def_count_table_0 {
    bool                                  hit;
    bool                                  reach;
    flow_def_count_table_0__action_type_t action_run;
    bit<32>                               count_action__idx;
    @matchKind("lpm") 
    bit<32>                               key_count_table_0_hdr_ipv4_srcAddr__val;
    @matchKind("lpm") 
    bit<32>                               key_count_table_0_hdr_ipv4_srcAddr__prefix;
}

@controlled() extern flow_def_count_table_0 query_count_table_0(@matchKind("lpm") in bit<32> count_table_0_hdr_ipv4_srcAddr);
extern void end_count_table_0();
enum flow_def_t3_0__action_type_t {
    use_H12,
    NoAction_10
}

struct flow_def_t3_0 {
    bool                         hit;
    bool                         reach;
    flow_def_t3_0__action_type_t action_run;
    @matchKind("exact") 
    bit<32>                      key_t3_0_header1;
    @matchKind("exact") 
    bit<8>                       key_t3_0_hdr_ipv4_ttl;
}

@controlled() extern flow_def_t3_0 query_t3_0(@matchKind("exact") in bit<32> t3_0_header1, @matchKind("exact") in bit<8> t3_0_hdr_ipv4_ttl);
extern void end_t3_0();
extern void key_match(in bool condition);
extern void angelic_assert(in bool condition);
extern void bug();

#include <core.p4>

#include <v1model.p4>

struct custom_metadata_t {
    bit<32> nhop_ipv4;
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
    bit<32> _custom_metadata_nhop_ipv40;
}

struct headers {
    ethernet_t ethernet;
    ipv4_t     ipv4;
    tcp_t      tcp;
}

parser ParserImpl(packet_in packet, out headers hdr, inout metadata meta, inout standard_metadata_t standard_metadata) {
    state parse_ipv4 {
        packet.extract<ipv4_t>(hdr.ipv4);
        transition select(hdr.ipv4.protocol) {
            8w6: parse_tcp;
            default: accept;
        }
    }
    state parse_tcp {
        packet.extract<tcp_t>(hdr.tcp);
        transition accept;
    }
    state start {
        packet.extract<ethernet_t>(hdr.ethernet);
        transition select(hdr.ethernet.etherType) {
            16w0x800: parse_ipv4;
            default: accept;
        }
    }
}

control egress(inout headers hdr, inout metadata meta, inout standard_metadata_t standard_metadata) {
    bit<32> key_0;
    apply {
        hdr.ipv4.setInvalid();
        hdr.ethernet.setInvalid();
        {
            flow_def_t1_0 t1;
            t1 = query_t1_0(hdr.ipv4.srcAddr);
            if (t1.hit) {
                key_match(hdr.ipv4.srcAddr == t1.key_t1_0_hdr_ipv4_srcAddr);
                if (!hdr.ipv4.isValid())  {
                    bug();
                } 
            }
            if (t1.action_run == flow_def_t1_0__action_type_t.NoAction_1) {
            }
            else  {
                if (t1.action_run == flow_def_t1_0__action_type_t._drop_2) {
                    angelic_assert(true);
                    {
                        standard_metadata.egress_spec = 9w511;
                    }
                }
                else  {
                    if (t1.action_run == flow_def_t1_0__action_type_t.validate_H1) {
                        angelic_assert(true);
                        {
                            hdr.ipv4.setValid();
                        }
                    }
                    else  {
                        ;
                    }
                }
            }
            end_t1_0();
        }
        {
            flow_def_t2_0 t2;
            t2 = query_t2_0(hdr.ipv4.dstAddr);
            if (t2.hit) {
                key_match(hdr.ipv4.dstAddr == t2.key_t2_0_hdr_ipv4_dstAddr);
                if (!hdr.ipv4.isValid())  {
                    bug();
                } 
            }
            if (t2.action_run == flow_def_t2_0__action_type_t.NoAction_9) {
            }
            else  {
                if (t2.action_run == flow_def_t2_0__action_type_t._drop_7) {
                    angelic_assert(true);
                    {
                        standard_metadata.egress_spec = 9w511;
                    }
                }
                else  {
                    if (t2.action_run == flow_def_t2_0__action_type_t.validate_H2) {
                        angelic_assert(true);
                        {
                            hdr.ethernet.setValid();
                        }
                    }
                    else  {
                        ;
                    }
                }
            }
            end_t2_0();
        }
        if (hdr.ipv4.isValid() && hdr.ipv4.isValid())  {
            key_0 = hdr.ipv4.srcAddr + hdr.ipv4.dstAddr;
        } 
        else  {
            bug();
        }
        {
            flow_def_t3_0 t3;
            t3 = query_t3_0(key_0, hdr.ipv4.ttl);
            if (t3.hit) {
                key_match(key_0 == t3.key_t3_0_header1 && hdr.ipv4.ttl == t3.key_t3_0_hdr_ipv4_ttl);
                if (!hdr.ipv4.isValid())  {
                    bug();
                } 
            }
            if (t3.action_run == flow_def_t3_0__action_type_t.NoAction_10) {
            }
            else  {
                if (t3.action_run == flow_def_t3_0__action_type_t.use_H12) {
                    angelic_assert(true);
                    {
                        if (hdr.ipv4.isValid() && hdr.ipv4.isValid())  {
                            hdr.ipv4.srcAddr = hdr.ipv4.dstAddr;
                        } 
                        else  {
                            bug();
                        }
                        if (hdr.ethernet.isValid() && hdr.ethernet.isValid())  {
                            hdr.ethernet.srcAddr = hdr.ethernet.dstAddr;
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
            end_t3_0();
        }
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

control ingress(inout headers hdr, inout metadata meta, inout standard_metadata_t standard_metadata) {
    bool __track_egress_spec_0;
    @name("ingress.ip_src_counter") counter(32w1024, CounterType.packets) ip_src_counter_0;
    apply {
        __track_egress_spec_0 = false;
        {
            flow_def_count_table_0 count_table;
            count_table = query_count_table_0(hdr.ipv4.srcAddr);
            if (count_table.hit) {
                key_match(hdr.ipv4.srcAddr & (32w1 << count_table.key_count_table_0_hdr_ipv4_srcAddr__prefix) - 32w1 == count_table.key_count_table_0_hdr_ipv4_srcAddr__val & (32w1 << count_table.key_count_table_0_hdr_ipv4_srcAddr__prefix) - 32w1);
                if (!(hdr.ipv4.isValid() || (32w1 << count_table.key_count_table_0_hdr_ipv4_srcAddr__prefix) - 32w1 == 32w0))  {
                    bug();
                } 
            }
            if (count_table.action_run == flow_def_count_table_0__action_type_t.NoAction_11) {
            }
            else  {
                if (count_table.action_run == flow_def_count_table_0__action_type_t._drop_8) {
                    angelic_assert(true);
                    {
                        standard_metadata.egress_spec = 9w511;
                        __track_egress_spec_0 = true;
                    }
                }
                else  {
                    if (count_table.action_run == flow_def_count_table_0__action_type_t.count_action) {
                        angelic_assert(true);
                        {
                            if (count_table.count_action__idx >= 32w1024)  {
                                bug();
                            } 
                            ip_src_counter_0.count(count_table.count_action__idx);
                        }
                    }
                    else  {
                        ;
                    }
                }
            }
            end_count_table_0();
        }
        {
            flow_def_ipv4_lpm_0 ipv4_lpm;
            ipv4_lpm = query_ipv4_lpm_0(hdr.ipv4.dstAddr);
            if (ipv4_lpm.hit) {
                key_match(hdr.ipv4.dstAddr & (32w1 << ipv4_lpm.key_ipv4_lpm_0_hdr_ipv4_dstAddr__prefix) - 32w1 == ipv4_lpm.key_ipv4_lpm_0_hdr_ipv4_dstAddr__val & (32w1 << ipv4_lpm.key_ipv4_lpm_0_hdr_ipv4_dstAddr__prefix) - 32w1);
                if (!(hdr.ipv4.isValid() || (32w1 << ipv4_lpm.key_ipv4_lpm_0_hdr_ipv4_dstAddr__prefix) - 32w1 == 32w0))  {
                    bug();
                } 
            }
            if (ipv4_lpm.action_run == flow_def_ipv4_lpm_0__action_type_t.NoAction_13) {
            }
            else  {
                if (ipv4_lpm.action_run == flow_def_ipv4_lpm_0__action_type_t._drop_10) {
                    angelic_assert(true);
                    {
                        standard_metadata.egress_spec = 9w511;
                        __track_egress_spec_0 = true;
                    }
                }
                else  {
                    if (ipv4_lpm.action_run == flow_def_ipv4_lpm_0__action_type_t.set_nhop) {
                        angelic_assert(true);
                        {
                            meta._custom_metadata_nhop_ipv40 = ipv4_lpm.set_nhop__nhop_ipv4;
                            standard_metadata.egress_spec = ipv4_lpm.set_nhop__port;
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
                        ;
                    }
                }
            }
            end_ipv4_lpm_0();
        }
        {
            flow_def_forward_0 forward;
            forward = query_forward_0(meta._custom_metadata_nhop_ipv40);
            if (forward.hit) {
                key_match(meta._custom_metadata_nhop_ipv40 == forward.key_forward_0_meta_custom_metadata_nhop_ipv4);
            }
            if (forward.action_run == flow_def_forward_0__action_type_t.NoAction_12) {
            }
            else  {
                if (forward.action_run == flow_def_forward_0__action_type_t._drop_9) {
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

struct tuple_0 {
    bit<4>  field;
    bit<4>  field_0;
    bit<8>  field_1;
    bit<16> field_2;
    bit<16> field_3;
    bit<3>  field_4;
    bit<13> field_5;
    bit<8>  field_6;
    bit<8>  field_7;
    bit<32> field_8;
    bit<32> field_9;
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
