enum flow_def_ipv4_lpm_0__action_type_t {
    ipv4_forward,
    drop_1,
    NoAction_0
}

struct flow_def_ipv4_lpm_0 {
    bool                               hit;
    bool                               reach;
    flow_def_ipv4_lpm_0__action_type_t action_run;
    bit<48>                            ipv4_forward__dstAddr;
    bit<9>                             ipv4_forward__port;
    @matchKind("lpm") 
    bit<32>                            key_ipv4_lpm_0_hdr_ipv4_dstAddr__val;
    @matchKind("lpm") 
    bit<32>                            key_ipv4_lpm_0_hdr_ipv4_dstAddr__prefix;
}

@controlled() extern flow_def_ipv4_lpm_0 query_ipv4_lpm_0(@matchKind("lpm") in bit<32> ipv4_lpm_0_hdr_ipv4_dstAddr);
extern void end_ipv4_lpm_0();
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

struct metadata {
}

struct headers {
    ethernet_t ethernet;
    ipv4_t     ipv4;
}

parser MyParser(packet_in packet, out headers hdr, inout metadata meta, inout standard_metadata_t standard_metadata) {
    state start {
        packet.extract<ethernet_t>(hdr.ethernet);
        transition select(hdr.ethernet.etherType) {
            16w0x800: parse_ipv4;
            default: accept;
        }
    }
    state parse_ipv4 {
        packet.extract<ipv4_t>(hdr.ipv4);
        transition accept;
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
        if (hdr.ipv4.isValid()) {
            flow_def_ipv4_lpm_0 ipv4_lpm;
            ipv4_lpm = query_ipv4_lpm_0(hdr.ipv4.dstAddr);
            if (ipv4_lpm.hit) {
                key_match(hdr.ipv4.dstAddr & (32w1 << ipv4_lpm.key_ipv4_lpm_0_hdr_ipv4_dstAddr__prefix) - 32w1 == ipv4_lpm.key_ipv4_lpm_0_hdr_ipv4_dstAddr__val & (32w1 << ipv4_lpm.key_ipv4_lpm_0_hdr_ipv4_dstAddr__prefix) - 32w1);
                if (!(hdr.ipv4.isValid() || (32w1 << ipv4_lpm.key_ipv4_lpm_0_hdr_ipv4_dstAddr__prefix) - 32w1 == 32w0))  {
                    bug();
                } 
            }
            if (ipv4_lpm.action_run == flow_def_ipv4_lpm_0__action_type_t.NoAction_0) {
                angelic_assert(true);
                {
                }
            }
            else  {
                if (ipv4_lpm.action_run == flow_def_ipv4_lpm_0__action_type_t.drop_1) {
                    angelic_assert(true);
                    {
                        standard_metadata.egress_spec = 9w511;
                        __track_egress_spec_0 = true;
                    }
                }
                else  {
                    if (ipv4_lpm.action_run == flow_def_ipv4_lpm_0__action_type_t.ipv4_forward) {
                        angelic_assert(true);
                        {
                            standard_metadata.egress_spec = ipv4_lpm.ipv4_forward__port;
                            __track_egress_spec_0 = true;
                            if (hdr.ethernet.isValid() && hdr.ethernet.isValid())  {
                                hdr.ethernet.srcAddr = hdr.ethernet.dstAddr;
                            } 
                            else  {
                                bug();
                            }
                            if (hdr.ethernet.isValid())  {
                                hdr.ethernet.dstAddr = ipv4_lpm.ipv4_forward__dstAddr;
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
            end_ipv4_lpm_0();
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
        packet.emit<ethernet_t>(hdr.ethernet);
        packet.emit<ipv4_t>(hdr.ipv4);
    }
}

V1Switch<headers, metadata>(MyParser(), MyVerifyChecksum(), MyIngress(), MyEgress(), MyComputeChecksum(), MyDeparser()) main;

void copy_field_list(in metadata from, inout metadata to, in standard_metadata_t smfrom, inout standard_metadata_t smto, in bit<16> discriminator) {
}
