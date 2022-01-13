
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
    @name(".NoAction") action NoAction_0() {
    }
    @name(".NoAction") action NoAction_1() {
    }
    @name(".NoAction") action NoAction_7() {
    }
    @name("egress._drop") action _drop() {
        standard_metadata.egress_spec = 9w511;
    }
    @name("egress._drop") action _drop_2() {
        standard_metadata.egress_spec = 9w511;
    }
    @name("egress.validate_H1") action validate_H1() {
        hdr.ipv4.setValid();
    }
    @name("egress.validate_H2") action validate_H2() {
        hdr.ethernet.setValid();
    }
    @name("egress.use_H12") action use_H12() {
        hdr.ipv4.srcAddr = hdr.ipv4.dstAddr;
        hdr.ethernet.srcAddr = hdr.ethernet.dstAddr;
    }
    @name("egress.t1") table t1_0 {
        key = {
            hdr.ipv4.srcAddr: exact @name("hdr.ipv4.srcAddr") ;
        }
        actions = {
            validate_H1();
            _drop();
            @defaultonly NoAction_0();
        }
        default_action = NoAction_0();
    }
    @name("egress.t2") table t2_0 {
        key = {
            hdr.ipv4.dstAddr: exact @name("hdr.ipv4.dstAddr") ;
        }
        actions = {
            validate_H2();
            _drop_2();
            @defaultonly NoAction_1();
        }
        default_action = NoAction_1();
    }
    @name("egress.t3") table t3_0 {
        key = {
            key_0       : exact @name("header1") ;
            hdr.ipv4.ttl: exact @name("hdr.ipv4.ttl") ;
        }
        actions = {
            use_H12();
            @defaultonly NoAction_7();
        }
        default_action = NoAction_7();
    }
    apply {
        hdr.ipv4.setInvalid();
        hdr.ethernet.setInvalid();
        t1_0.apply();
        t2_0.apply();
        key_0 = hdr.ipv4.srcAddr + hdr.ipv4.dstAddr;
        t3_0.apply();
    }
}

control ingress(inout headers hdr, inout metadata meta, inout standard_metadata_t standard_metadata) {
    @name(".NoAction") action NoAction_8() {
    }
    @name(".NoAction") action NoAction_9() {
    }
    @name("ingress._drop") action _drop_5() {
        standard_metadata.egress_spec = 9w511;
    }
    @name("ingress._drop") action _drop_6() {
        standard_metadata.egress_spec = 9w511;
    }
    @name("ingress.set_dmac") action set_dmac(bit<48> dmac) {
        hdr.ethernet.dstAddr = dmac;
    }
    @name("ingress.set_nhop") action set_nhop(bit<32> nhop_ipv4, bit<9> port) {
        meta._custom_metadata_nhop_ipv40 = nhop_ipv4;
        standard_metadata.egress_spec = port;
        hdr.ipv4.ttl = hdr.ipv4.ttl + 8w255;
    }
    @name("ingress.forward") table forward_0 {
        actions = {
            set_dmac();
            _drop_5();
            @defaultonly NoAction_8();
        }
        key = {
            meta._custom_metadata_nhop_ipv40: exact @name("meta.custom_metadata.nhop_ipv4") ;
        }
        size = 512;
        default_action = NoAction_8();
    }
    @name("ingress.ipv4_lpm") table ipv4_lpm_0 {
        actions = {
            set_nhop();
            _drop_6();
            @defaultonly NoAction_9();
        }
        key = {
            hdr.ipv4.dstAddr: lpm @name("hdr.ipv4.dstAddr") ;
        }
        size = 1024;
        default_action = NoAction_9();
    }
    apply {
        ipv4_lpm_0.apply();
        forward_0.apply();
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
        verify_checksum<tuple_0, bit<16>>(true, { hdr.ipv4.version, hdr.ipv4.ihl, hdr.ipv4.diffserv, hdr.ipv4.totalLen, hdr.ipv4.identification, hdr.ipv4.flags, hdr.ipv4.fragOffset, hdr.ipv4.ttl, hdr.ipv4.protocol, hdr.ipv4.srcAddr, hdr.ipv4.dstAddr }, hdr.ipv4.hdrChecksum, HashAlgorithm.csum16);
    }
}

control computeChecksum(inout headers hdr, inout metadata meta) {
    apply {
        update_checksum<tuple_0, bit<16>>(true, { hdr.ipv4.version, hdr.ipv4.ihl, hdr.ipv4.diffserv, hdr.ipv4.totalLen, hdr.ipv4.identification, hdr.ipv4.flags, hdr.ipv4.fragOffset, hdr.ipv4.ttl, hdr.ipv4.protocol, hdr.ipv4.srcAddr, hdr.ipv4.dstAddr }, hdr.ipv4.hdrChecksum, HashAlgorithm.csum16);
    }
}

V1Switch<headers, metadata>(ParserImpl(), verifyChecksum(), ingress(), egress(), computeChecksum(), DeparserImpl()) main;

void copy_field_list(in metadata from, inout metadata to, in standard_metadata_t smfrom, inout standard_metadata_t smto, in bit<16> discriminator) {
    ;
}
