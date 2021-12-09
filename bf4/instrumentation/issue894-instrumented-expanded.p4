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
enum flow_def_forward_0__action_type_t {
    set_dmac,
    _drop_5,
    NoAction_7
}

struct flow_def_forward_0 {
    bool                              hit;
    bool                              reach;
    flow_def_forward_0__action_type_t action_run;
    bit<48>                           set_dmac__dmac;
    @matchKind("exact") 
    bit<32>                           key_forward_0_custom_metadata_nhop_ipv4;
}

@controlled() extern flow_def_forward_0 query_forward_0(@matchKind("exact") in bit<32> forward_0_custom_metadata_nhop_ipv4);
extern void end_forward_0();
enum flow_def_ipv4_lpm_0__action_type_t {
    set_nhop,
    _drop_6,
    NoAction_8
}

struct flow_def_ipv4_lpm_0 {
    bool                               hit;
    bool                               reach;
    flow_def_ipv4_lpm_0__action_type_t action_run;
    bit<32>                            set_nhop__nhop_ipv4;
    bit<9>                             set_nhop__port;
    @matchKind("lpm") 
    bit<32>                            key_ipv4_lpm_0_ipv4_dstAddr__val;
    @matchKind("lpm") 
    bit<32>                            key_ipv4_lpm_0_ipv4_dstAddr__prefix;
}

@controlled() extern flow_def_ipv4_lpm_0 query_ipv4_lpm_0(@matchKind("lpm") in bit<32> ipv4_lpm_0_ipv4_dstAddr);
extern void end_ipv4_lpm_0();
enum flow_def_set_heavy_hitter_count_table_0__action_type_t {
    set_heavy_hitter_count
}

struct flow_def_set_heavy_hitter_count_table_0 {
    bool                                                   hit;
    bool                                                   reach;
    flow_def_set_heavy_hitter_count_table_0__action_type_t action_run;
}

@controlled() extern flow_def_set_heavy_hitter_count_table_0 query_set_heavy_hitter_count_table_0();
extern void end_set_heavy_hitter_count_table_0();
enum flow_def_drop_heavy_hitter_table_0__action_type_t {
    _drop_2
}

struct flow_def_drop_heavy_hitter_table_0 {
    bool                                              hit;
    bool                                              reach;
    flow_def_drop_heavy_hitter_table_0__action_type_t action_run;
}

@controlled() extern flow_def_drop_heavy_hitter_table_0 query_drop_heavy_hitter_table_0();
extern void end_drop_heavy_hitter_table_0();
extern void key_match(in bool condition);
extern void angelic_assert(in bool condition);
extern void bug();

#include <core.p4>

#include <v1model.p4>

struct custom_metadata_t {
    bit<32> nhop_ipv4;
    bit<16> hash_val1;
    bit<16> hash_val2;
    bit<16> count_val1;
    bit<16> count_val2;
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
    bit<16> _custom_metadata_hash_val11;
    bit<16> _custom_metadata_hash_val22;
    bit<16> _custom_metadata_count_val13;
    bit<16> _custom_metadata_count_val24;
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

@name(".heavy_hitter_counter1") register<bit<16>>(32w16) heavy_hitter_counter1;

@name(".heavy_hitter_counter2") register<bit<16>>(32w16) heavy_hitter_counter2;

struct tuple_0 {
    bit<32> field;
    bit<32> field_0;
    bit<8>  field_1;
    bit<16> field_2;
    bit<16> field_3;
}

control ingress(inout headers hdr, inout metadata meta, inout standard_metadata_t standard_metadata) {
    bool __track_egress_spec_0;
    apply {
        __track_egress_spec_0 = false;
        {
            flow_def_set_heavy_hitter_count_table_0 set_heavy_hitter_count_table;
            set_heavy_hitter_count_table = query_set_heavy_hitter_count_table_0();
            ;
            if (set_heavy_hitter_count_table.action_run == flow_def_set_heavy_hitter_count_table_0__action_type_t.set_heavy_hitter_count) {
                angelic_assert(true);
                {
                    hash<bit<16>, bit<16>, tuple_0, bit<32>>(meta._custom_metadata_hash_val11, HashAlgorithm.csum16, 16w0, tuple_0 {field = hdr.ipv4.srcAddr,field_0 = hdr.ipv4.dstAddr,field_1 = hdr.ipv4.protocol,field_2 = hdr.tcp.srcPort,field_3 = hdr.tcp.dstPort}, 32w16);
                    if ((bit<32>)meta._custom_metadata_hash_val11 >= 32w16)  {
                        bug();
                    } 
                    heavy_hitter_counter1.read(meta._custom_metadata_count_val13, (bit<32>)meta._custom_metadata_hash_val11);
                    meta._custom_metadata_count_val13 = meta._custom_metadata_count_val13 + 16w1;
                    if ((bit<32>)meta._custom_metadata_hash_val11 >= 32w16)  {
                        bug();
                    } 
                    heavy_hitter_counter1.write((bit<32>)meta._custom_metadata_hash_val11, meta._custom_metadata_count_val13);
                    hash<bit<16>, bit<16>, tuple_0, bit<32>>(meta._custom_metadata_hash_val22, HashAlgorithm.crc16, 16w0, tuple_0 {field = hdr.ipv4.srcAddr,field_0 = hdr.ipv4.dstAddr,field_1 = hdr.ipv4.protocol,field_2 = hdr.tcp.srcPort,field_3 = hdr.tcp.dstPort}, 32w16);
                    if ((bit<32>)meta._custom_metadata_hash_val22 >= 32w16)  {
                        bug();
                    } 
                    heavy_hitter_counter2.read(meta._custom_metadata_count_val24, (bit<32>)meta._custom_metadata_hash_val22);
                    meta._custom_metadata_count_val24 = meta._custom_metadata_count_val24 + 16w1;
                    if ((bit<32>)meta._custom_metadata_hash_val22 >= 32w16)  {
                        bug();
                    } 
                    heavy_hitter_counter2.write((bit<32>)meta._custom_metadata_hash_val22, meta._custom_metadata_count_val24);
                }
            }
            else  {
                ;
            }
            end_set_heavy_hitter_count_table_0();
        }
        if (meta._custom_metadata_count_val13 > 16w100 && meta._custom_metadata_count_val24 > 16w100) {
            flow_def_drop_heavy_hitter_table_0 drop_heavy_hitter_table;
            drop_heavy_hitter_table = query_drop_heavy_hitter_table_0();
            ;
            if (drop_heavy_hitter_table.action_run == flow_def_drop_heavy_hitter_table_0__action_type_t._drop_2) {
                angelic_assert(true);
                {
                    standard_metadata.egress_spec = 9w511;
                    __track_egress_spec_0 = true;
                }
            }
            else  {
                ;
            }
            end_drop_heavy_hitter_table_0();
        }
        else {
            {
                flow_def_ipv4_lpm_0 ipv4_lpm;
                ipv4_lpm = query_ipv4_lpm_0(hdr.ipv4.dstAddr);
                if (ipv4_lpm.hit) {
                    key_match(hdr.ipv4.dstAddr & (32w1 << ipv4_lpm.key_ipv4_lpm_0_ipv4_dstAddr__prefix) - 32w1 == ipv4_lpm.key_ipv4_lpm_0_ipv4_dstAddr__val & (32w1 << ipv4_lpm.key_ipv4_lpm_0_ipv4_dstAddr__prefix) - 32w1);
                    if (!(hdr.ipv4.isValid() || (32w1 << ipv4_lpm.key_ipv4_lpm_0_ipv4_dstAddr__prefix) - 32w1 == 32w0))  {
                        bug();
                    } 
                }
                if (ipv4_lpm.action_run == flow_def_ipv4_lpm_0__action_type_t.NoAction_8) {
                }
                else  {
                    if (ipv4_lpm.action_run == flow_def_ipv4_lpm_0__action_type_t._drop_6) {
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
                    key_match(meta._custom_metadata_nhop_ipv40 == forward.key_forward_0_custom_metadata_nhop_ipv4);
                }
                if (forward.action_run == flow_def_forward_0__action_type_t.NoAction_7) {
                }
                else  {
                    if (forward.action_run == flow_def_forward_0__action_type_t._drop_5) {
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

struct tuple_1 {
    bit<4>  field_4;
    bit<4>  field_5;
    bit<8>  field_6;
    bit<16> field_7;
    bit<16> field_8;
    bit<3>  field_9;
    bit<13> field_10;
    bit<8>  field_11;
    bit<8>  field_12;
    bit<32> field_13;
    bit<32> field_14;
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
