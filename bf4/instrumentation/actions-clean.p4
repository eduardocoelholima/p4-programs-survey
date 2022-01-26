
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

struct metadata {
    bit<1> _ing_metadata_drop0;
    bit<9> _ing_metadata_egress_port1;
    bit<4> _ing_metadata_packet_type2;
}

struct headers {
    @name(".ethernet") 
    ethernet_t ethernet;
    @name(".ipv4") 
    ipv4_t     ipv4;
    ipv4_t     ipv4_2;
}

parser ParserImpl(packet_in packet, out headers hdr, inout metadata meta, inout standard_metadata_t standard_metadata) {
    @name(".parse_ipv4") state parse_ipv4 {
        packet.extract<ipv4_t>(hdr.ipv4);
        transition reject;
    }
    @name(".start") state start {
        packet.extract<ethernet_t>(hdr.ethernet);
        transition select(hdr.ethernet.etherType) {
            16w0x800: parse_ipv4;
            default: accept;
        }
    }
}

control egress(inout headers hdr, inout metadata meta, inout standard_metadata_t standard_metadata) {
    apply {
    }
}

control ingress(inout headers hdr, inout metadata meta, inout standard_metadata_t standard_metadata) {
    @name(".NoAction") action NoAction_0() {
    }
    @name(".NoAction") action NoAction_3() {
    }
    @name("ingress.drop_") action drop_1() {
    }
    @name("ingress.drop_") action drop_3() {
    }
    @name("ingress.validate_2") action validate_0() {
        hdr.ipv4_2.setValid();
    }
    @name("ingress.use_2") action use_0() {
        hdr.ipv4_2.ttl = hdr.ipv4_2.ttl + 8w255;
    }
    @name("ingress.t1") table t1_0 {
        key = {
            hdr.ethernet.etherType: exact @name("ethernet.etherType") ;
        }
        actions = {
            validate_0();
            drop_1();
            @defaultonly NoAction_0();
        }
        default_action = NoAction_0();
    }
    @name("ingress.t2") table t2_0 {
        key = {
            hdr.ethernet.etherType: exact @name("ethernet.etherType") ;
        }
        actions = {
            use_0();
            drop_3();
            @defaultonly NoAction_3();
        }
        default_action = NoAction_3();
    }
    apply {
        t1_0.apply();
        t2_0.apply();
        standard_metadata.egress_spec = 9w5;
    }
}

control DeparserImpl(packet_out packet, in headers hdr) {
    apply {
        packet.emit<ethernet_t>(hdr.ethernet);
        packet.emit<ipv4_t>(hdr.ipv4);
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
    ;
}
