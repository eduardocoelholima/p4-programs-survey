extern H havoc<H>();
extern void key_match(in bool condition);
extern void assert(in bool condition);
extern void angelic_assert(in bool condition);
extern void assume(in bool condition);
extern void bug();
extern void oob();
extern void dontCare();
extern void do_drop();

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
    bool __track_egress_spec;
    @name(".NoAction") action NoAction_0() {
    }
    @name(".NoAction") action NoAction_4() {
    }
    @name(".NoAction") action NoAction_5() {
    }
    @name("MyIngress.drop") action drop_1() {
        {
            standard_metadata.egress_spec = 9w511;
            __track_egress_spec = true;
        }
    }
    @name("MyIngress.drop") action drop_3() {
        {
            standard_metadata.egress_spec = 9w511;
            __track_egress_spec = true;
        }
    }
    @name("MyIngress.ctrl") action ctrl() {
        {
            standard_metadata.egress_spec = 9w510;
            __track_egress_spec = true;
        }
    }
    @name("MyIngress.l2_valid") @instrument_keys() table l2_valid {
        key = {
            hdr.ethernet.srcAddr: exact @name("hdr.ethernet.srcAddr") ;
        }
        actions = {
            drop_1();
            NoAction_0();
        }
        default_action = NoAction_0();
    }
    @name("MyIngress.l3_valid") @instrument_keys() table l3_valid {
        key = {
            hdr.ipv4.ttl: exact @name("hdr.ipv4.ttl") ;
        }
        actions = {
            drop_3();
            NoAction_4();
        }
        default_action = NoAction_4();
    }
    @name("MyIngress.punt") @instrument_keys() table punt {
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
        __track_egress_spec = false;
        l2_valid.apply();
        l3_valid.apply();
        punt.apply();
        if (!__track_egress_spec)  {
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
