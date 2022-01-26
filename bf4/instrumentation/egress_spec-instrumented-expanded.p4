enum flow_def_l3_valid_0__action_type_t {
    drop_3,
    NoAction_4
}

struct flow_def_l3_valid_0 {
    bool                               hit;
    bool                               reach;
    flow_def_l3_valid_0__action_type_t action_run;
    @matchKind("exact") 
    bit<8>                             key_l3_valid_0_hdr_ipv4_ttl;
}

@controlled() extern flow_def_l3_valid_0 query_l3_valid_0(@matchKind("exact") in bit<8> l3_valid_0_hdr_ipv4_ttl);
extern void end_l3_valid_0();
enum flow_def_l2_valid_0__action_type_t {
    drop_1,
    NoAction_0
}

struct flow_def_l2_valid_0 {
    bool                               hit;
    bool                               reach;
    flow_def_l2_valid_0__action_type_t action_run;
    @matchKind("exact") 
    bit<48>                            key_l2_valid_0_hdr_ethernet_srcAddr;
}

@controlled() extern flow_def_l2_valid_0 query_l2_valid_0(@matchKind("exact") in bit<48> l2_valid_0_hdr_ethernet_srcAddr);
extern void end_l2_valid_0();
enum flow_def_punt_0__action_type_t {
    ctrl,
    NoAction_5
}

struct flow_def_punt_0 {
    bool                           hit;
    bool                           reach;
    flow_def_punt_0__action_type_t action_run;
    @matchKind("ternary") 
    bit<48>                        key_punt_0_hdr_ethernet_dstAddr__val;
    @matchKind("ternary") 
    bit<48>                        key_punt_0_hdr_ethernet_dstAddr__mask;
    @matchKind("ternary") 
    bit<32>                        key_punt_0_hdr_ipv4_dstAddr__val;
    @matchKind("ternary") 
    bit<32>                        key_punt_0_hdr_ipv4_dstAddr__mask;
}

@controlled() extern flow_def_punt_0 query_punt_0(@matchKind("ternary") in bit<48> punt_0_hdr_ethernet_dstAddr, @matchKind("ternary") in bit<32> punt_0_hdr_ipv4_dstAddr);
extern void end_punt_0();
extern void key_match(in bool condition);
extern void angelic_assert(in bool condition);
extern void bug();

#include <core.p4>

#include <v1model.p4>

typedef bit<48> macAddr_t;
typedef bit<32> ip4Addr_t;
header ethernet_t {
    macAddr_t dstAddr;
    macAddr_t srcAddr;
    bit<16>   etherType;
}

header ipv4_t {
    bit<4>    version;
    bit<4>    ihl;
    bit<8>    diffserv;
    bit<16>   totalLen;
    bit<16>   identification;
    bit<3>    flags;
    bit<13>   fragOffset;
    bit<8>    ttl;
    bit<8>    protocol;
    bit<16>   hdrChecksum;
    ip4Addr_t srcAddr;
    ip4Addr_t dstAddr;
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

struct metadata {
    bit<1> l3_admit;
}

struct headers {
    ethernet_t ethernet;
    ipv4_t     ipv4;
    ipv6_t     ipv6;
}

parser MyParser(packet_in packet, out headers hdr, inout metadata meta, inout standard_metadata_t standard_metadata) {
    state parse_ipv4 {
        packet.extract<ipv4_t>(hdr.ipv4);
        transition accept;
    }
    state start {
        packet.extract<ethernet_t>(hdr.ethernet);
        transition select(hdr.ethernet.etherType) {
            16w0x800: parse_ipv4;
            default: reject;
        }
    }
}

control MyVerifyChecksum(inout headers hdr, inout metadata meta) {
    apply {
    }
}

control MyIngress(inout headers hdr, inout metadata meta, inout standard_metadata_t standard_metadata) {
    bool __track_egress_spec_0;
    apply {
        __track_egress_spec_0 = false;
        {
            flow_def_l2_valid_0 l2_valid;
            l2_valid = query_l2_valid_0(hdr.ethernet.srcAddr);
            if (l2_valid.hit) {
                key_match(hdr.ethernet.srcAddr == l2_valid.key_l2_valid_0_hdr_ethernet_srcAddr);
                if (!hdr.ethernet.isValid())  {
                    bug();
                } 
            }
            if (l2_valid.action_run == flow_def_l2_valid_0__action_type_t.NoAction_0) {
                angelic_assert(true);
                {
                }
            }
            else  {
                if (l2_valid.action_run == flow_def_l2_valid_0__action_type_t.drop_1) {
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
            end_l2_valid_0();
        }
        {
            flow_def_l3_valid_0 l3_valid;
            l3_valid = query_l3_valid_0(hdr.ipv4.ttl);
            if (l3_valid.hit) {
                key_match(hdr.ipv4.ttl == l3_valid.key_l3_valid_0_hdr_ipv4_ttl);
                if (!hdr.ipv4.isValid())  {
                    bug();
                } 
            }
            if (l3_valid.action_run == flow_def_l3_valid_0__action_type_t.NoAction_4) {
                angelic_assert(true);
                {
                }
            }
            else  {
                if (l3_valid.action_run == flow_def_l3_valid_0__action_type_t.drop_3) {
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
            end_l3_valid_0();
        }
        {
            flow_def_punt_0 punt;
            punt = query_punt_0(hdr.ethernet.dstAddr, hdr.ipv4.dstAddr);
            if (punt.hit) {
                key_match(hdr.ethernet.dstAddr & punt.key_punt_0_hdr_ethernet_dstAddr__mask == punt.key_punt_0_hdr_ethernet_dstAddr__val & punt.key_punt_0_hdr_ethernet_dstAddr__mask && hdr.ipv4.dstAddr & punt.key_punt_0_hdr_ipv4_dstAddr__mask == punt.key_punt_0_hdr_ipv4_dstAddr__val & punt.key_punt_0_hdr_ipv4_dstAddr__mask);
                if (!(hdr.ethernet.isValid() || punt.key_punt_0_hdr_ethernet_dstAddr__mask == 48w0))  {
                    bug();
                } 
                if (!(hdr.ipv4.isValid() || punt.key_punt_0_hdr_ipv4_dstAddr__mask == 32w0))  {
                    bug();
                } 
            }
            if (punt.action_run == flow_def_punt_0__action_type_t.NoAction_5) {
                angelic_assert(true);
                {
                }
            }
            else  {
                if (punt.action_run == flow_def_punt_0__action_type_t.ctrl) {
                    angelic_assert(true);
                    {
                        standard_metadata.egress_spec = 9w510;
                        __track_egress_spec_0 = true;
                    }
                }
                else  {
                    ;
                }
            }
            end_punt_0();
        }
        if (!__track_egress_spec_0)  {
            bug();
        } 
    }
}

control MyEgress(inout headers hdr, inout metadata meta, inout standard_metadata_t standard_metadata) {
    apply {
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

control MyComputeChecksum(inout headers hdr, inout metadata meta) {
    apply {
    }
}

control MyDeparser(packet_out packet, in headers hdr) {
    apply {
    }
}

V1Switch<headers, metadata>(MyParser(), MyVerifyChecksum(), MyIngress(), MyEgress(), MyComputeChecksum(), MyDeparser()) main;

void copy_field_list(in metadata from, inout metadata to, in standard_metadata_t smfrom, inout standard_metadata_t smto, in bit<16> discriminator) {
}
