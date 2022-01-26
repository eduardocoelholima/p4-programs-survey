
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
    @name(".NoAction") action NoAction_0() {
    }
    @name(".NoAction") action NoAction_4() {
    }
    @name(".NoAction") action NoAction_5() {
    }
    @name("MyIngress.drop") action drop_1() {
        standard_metadata.egress_spec = 9w511;
    }
    @name("MyIngress.drop") action drop_3() {
        standard_metadata.egress_spec = 9w511;
    }
    @name("MyIngress.l2_valid") table l2_valid_0 {
        key = {
            hdr.ethernet.srcAddr: exact @name("hdr.ethernet.srcAddr") ;
        }
        actions = {
            drop_1();
            NoAction_0();
        }
        default_action = NoAction_0();
    }
    @name("MyIngress.ctrl") action ctrl() {
        standard_metadata.egress_spec = 9w510;
    }
    @name("MyIngress.l3_valid") table l3_valid_0 {
        key = {
            hdr.ipv4.ttl: exact @name("hdr.ipv4.ttl") ;
        }
        actions = {
            drop_3();
            NoAction_4();
        }
        default_action = NoAction_4();
    }
    @name("MyIngress.punt") table punt_0 {
        key = {
            hdr.ethernet.dstAddr: ternary @name("hdr.ethernet.dstAddr") ;
            hdr.ipv4.dstAddr    : ternary @name("hdr.ipv4.dstAddr") ;
        }
        actions = {
            ctrl();
            NoAction_5();
        }
        default_action = NoAction_5();
    }
    apply {
        l2_valid_0.apply();
        l3_valid_0.apply();
        punt_0.apply();
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
        update_checksum<tuple_0, bit<16>>(hdr.ipv4.isValid(), { hdr.ipv4.version, hdr.ipv4.ihl, hdr.ipv4.diffserv, hdr.ipv4.totalLen, hdr.ipv4.identification, hdr.ipv4.flags, hdr.ipv4.fragOffset, hdr.ipv4.ttl, hdr.ipv4.protocol, hdr.ipv4.srcAddr, hdr.ipv4.dstAddr }, hdr.ipv4.hdrChecksum, HashAlgorithm.csum16);
    }
}

control MyDeparser(packet_out packet, in headers hdr) {
    apply {
    }
}

V1Switch<headers, metadata>(MyParser(), MyVerifyChecksum(), MyIngress(), MyEgress(), MyComputeChecksum(), MyDeparser()) main;

void copy_field_list(in metadata from, inout metadata to, in standard_metadata_t smfrom, inout standard_metadata_t smto, in bit<16> discriminator) {
    ;
}
