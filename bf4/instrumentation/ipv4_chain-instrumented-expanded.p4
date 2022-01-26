enum flow_def_get_type_0__action_type_t {
    packet_type,
    NoAction_0
}

struct flow_def_get_type_0 {
    bool                               hit;
    bool                               reach;
    flow_def_get_type_0__action_type_t action_run;
    bit<1>                             packet_type__is_l3;
    @matchKind("exact") 
    bit<16>                            key_get_type_0_hdr_ethernet_etherType;
}

@controlled() extern flow_def_get_type_0 query_get_type_0(@matchKind("exact") in bit<16> get_type_0_hdr_ethernet_etherType);
extern void end_get_type_0();
enum flow_def_fwd_1__action_type_t {
    fwd,
    NoAction_3
}

struct flow_def_fwd_1 {
    bool                          hit;
    bool                          reach;
    flow_def_fwd_1__action_type_t action_run;
    bit<9>                        fwd__port;
    @matchKind("exact") 
    bit<1>                        key_fwd_1_meta_l3_admit;
    @matchKind("exact") 
    bit<32>                       key_fwd_1_hdr_ipv4_dstAddr;
}

@controlled() extern flow_def_fwd_1 query_fwd_1(@matchKind("exact") in bit<1> fwd_1_meta_l3_admit, @matchKind("exact") in bit<32> fwd_1_hdr_ipv4_dstAddr);
extern void end_fwd_1();
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
            default: accept;
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
        {
            flow_def_get_type_0 get_type;
            get_type = query_get_type_0(hdr.ethernet.etherType);
            if (get_type.hit) {
                key_match(hdr.ethernet.etherType == get_type.key_get_type_0_hdr_ethernet_etherType);
                if (!hdr.ethernet.isValid())  {
                    bug();
                } 
            }
            if (get_type.action_run == flow_def_get_type_0__action_type_t.NoAction_0) {
            }
            else  {
                if (get_type.action_run == flow_def_get_type_0__action_type_t.packet_type) {
                    angelic_assert(true);
                    {
                        meta.l3_admit = get_type.packet_type__is_l3;
                    }
                }
                else  {
                    ;
                }
            }
            end_get_type_0();
        }
        {
            flow_def_fwd_1 fwd_0;
            fwd_0 = query_fwd_1(meta.l3_admit, hdr.ipv4.dstAddr);
            if (fwd_0.hit) {
                key_match(meta.l3_admit == fwd_0.key_fwd_1_meta_l3_admit && hdr.ipv4.dstAddr == fwd_0.key_fwd_1_hdr_ipv4_dstAddr);
                if (!hdr.ipv4.isValid())  {
                    bug();
                } 
            }
            if (fwd_0.action_run == flow_def_fwd_1__action_type_t.NoAction_3) {
            }
            else  {
                if (fwd_0.action_run == flow_def_fwd_1__action_type_t.fwd) {
                    angelic_assert(true);
                    {
                    }
                }
                else  {
                    ;
                }
            }
            end_fwd_1();
        }
        standard_metadata.egress_spec = 9w511;
        __track_egress_spec_0 = true;
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
