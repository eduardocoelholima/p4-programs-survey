enum flow_def_set_mcg_0__action_type_t {
    set_output_mcg,
    _drop_2,
    NoAction_1
}

struct flow_def_set_mcg_0 {
    bool                              hit;
    bool                              reach;
    flow_def_set_mcg_0__action_type_t action_run;
    bit<16>                           set_output_mcg__mcast_group;
    @matchKind("exact") 
    bit<32>                           key_set_mcg_0_ipv4_dstAddr;
}

@controlled() extern flow_def_set_mcg_0 query_set_mcg_0(@matchKind("exact") in bit<32> set_mcg_0_ipv4_dstAddr);
extern void end_set_mcg_0();
enum flow_def_nat_table_0__action_type_t {
    do_nat,
    _drop,
    NoAction_0
}

struct flow_def_nat_table_0 {
    bool                                hit;
    bool                                reach;
    flow_def_nat_table_0__action_type_t action_run;
    bit<32>                             do_nat__dst_ip;
    @matchKind("exact") 
    bit<16>                             key_nat_table_0_intrinsic_metadata_egress_rid;
    @matchKind("exact") 
    bit<32>                             key_nat_table_0_ipv4_dstAddr;
}

@controlled() extern flow_def_nat_table_0 query_nat_table_0(@matchKind("exact") in bit<16> nat_table_0_intrinsic_metadata_egress_rid, @matchKind("exact") in bit<32> nat_table_0_ipv4_dstAddr);
extern void end_nat_table_0();
extern void key_match(in bool condition);
extern void angelic_assert(in bool condition);
extern void bug();

#include <core.p4>

#include <v1model.p4>

struct intrinsic_metadata_t {
    bit<16> mcast_grp;
    bit<32> lf_field_list;
    bit<16> egress_rid;
    bit<32> ingress_global_timestamp;
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

header udp_t {
    bit<16> srcPort;
    bit<16> dstPort;
    bit<16> length_;
    bit<16> checksum;
}

struct metadata {
    bit<16> _intrinsic_metadata_mcast_grp0;
    bit<32> _intrinsic_metadata_lf_field_list1;
    bit<16> _intrinsic_metadata_egress_rid2;
    bit<32> _intrinsic_metadata_ingress_global_timestamp3;
}

struct headers {
    @name(".ethernet") 
    ethernet_t ethernet;
    @name(".ipv4") 
    ipv4_t     ipv4;
    @name(".udp") 
    udp_t      udp;
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
            8w0x11: parse_udp;
            default: accept;
        }
    }
    @name(".parse_udp") state parse_udp {
        packet.extract<udp_t>(hdr.udp);
        transition accept;
    }
    @name(".start") state start {
        transition parse_ethernet;
    }
}

control egress(inout headers hdr, inout metadata meta, inout standard_metadata_t standard_metadata) {
    apply {
        {
            flow_def_nat_table_0 nat_table;
            nat_table = query_nat_table_0(meta._intrinsic_metadata_egress_rid2, hdr.ipv4.dstAddr);
            if (nat_table.hit) {
                key_match(meta._intrinsic_metadata_egress_rid2 == nat_table.key_nat_table_0_intrinsic_metadata_egress_rid && hdr.ipv4.dstAddr == nat_table.key_nat_table_0_ipv4_dstAddr);
                if (!hdr.ipv4.isValid())  {
                    bug();
                } 
            }
            if (nat_table.action_run == flow_def_nat_table_0__action_type_t.NoAction_0) {
            }
            else  {
                if (nat_table.action_run == flow_def_nat_table_0__action_type_t._drop) {
                    angelic_assert(true);
                    {
                        standard_metadata.egress_spec = 9w511;
                    }
                }
                else  {
                    if (nat_table.action_run == flow_def_nat_table_0__action_type_t.do_nat) {
                        angelic_assert(true);
                        {
                            if (hdr.ipv4.isValid())  {
                                hdr.ipv4.dstAddr = nat_table.do_nat__dst_ip;
                            } 
                            else  {
                                bug();
                            }
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
            end_nat_table_0();
        }
    }
}

control ingress(inout headers hdr, inout metadata meta, inout standard_metadata_t standard_metadata) {
    bool __track_egress_spec_0;
    apply {
        __track_egress_spec_0 = false;
        {
            flow_def_set_mcg_0 set_mcg;
            set_mcg = query_set_mcg_0(hdr.ipv4.dstAddr);
            if (set_mcg.hit) {
                key_match(hdr.ipv4.dstAddr == set_mcg.key_set_mcg_0_ipv4_dstAddr);
                if (!hdr.ipv4.isValid())  {
                    bug();
                } 
            }
            if (set_mcg.action_run == flow_def_set_mcg_0__action_type_t.NoAction_1) {
            }
            else  {
                if (set_mcg.action_run == flow_def_set_mcg_0__action_type_t._drop_2) {
                    angelic_assert(true);
                    {
                        standard_metadata.egress_spec = 9w511;
                        __track_egress_spec_0 = true;
                    }
                }
                else  {
                    if (set_mcg.action_run == flow_def_set_mcg_0__action_type_t.set_output_mcg) {
                        angelic_assert(true);
                        {
                            meta._intrinsic_metadata_mcast_grp0 = set_mcg.set_output_mcg__mcast_group;
                        }
                    }
                    else  {
                        ;
                    }
                }
            }
            end_set_mcg_0();
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
        packet.emit<udp_t>(hdr.udp);
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

struct tuple_1 {
    bit<32> field_10;
    bit<32> field_11;
    bit<8>  field_12;
    bit<8>  field_13;
    bit<16> field_14;
    bit<16> field_15;
    bit<16> field_16;
    bit<16> field_17;
}

control computeChecksum(inout headers hdr, inout metadata meta) {
    apply {
    }
}

V1Switch<headers, metadata>(ParserImpl(), verifyChecksum(), ingress(), egress(), computeChecksum(), DeparserImpl()) main;

void copy_field_list(in metadata from, inout metadata to, in standard_metadata_t smfrom, inout standard_metadata_t smto, in bit<16> discriminator) {
}
