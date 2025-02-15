
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
    @name(".NoAction") action NoAction_0() {
    }
    @name("egress.rewrite_mac") action rewrite_mac(bit<48> smac) {
        hdr.ethernet.srcAddr = smac;
    }
    @name("egress._drop") action _drop() {
        standard_metadata.egress_spec = 9w511;
    }
    @name("egress.send_frame") table send_frame_0 {
        actions = {
            rewrite_mac();
            _drop();
            @defaultonly NoAction_0();
        }
        key = {
            standard_metadata.egress_port: exact @name("standard_metadata.egress_port") ;
        }
        size = 256;
        default_action = NoAction_0();
    }
    apply {
        send_frame_0.apply();
    }
}

struct tuple_0 {
    bit<32> field;
    bit<32> field_0;
    bit<8>  field_1;
    bit<16> field_2;
    bit<16> field_3;
}

control ingress(inout headers hdr, inout metadata meta, inout standard_metadata_t standard_metadata) {
    @name(".NoAction") action NoAction_1() {
    }
    @name(".NoAction") action NoAction_7() {
    }
    @name(".NoAction") action NoAction_8() {
    }
    @name(".NoAction") action NoAction_9() {
    }
    @name("ingress.heavy_hitter_counter1") register<bit<16>>(32w16) heavy_hitter_counter1_0;
    @name("ingress.heavy_hitter_counter2") register<bit<16>>(32w16) heavy_hitter_counter2_0;
    @name("ingress._drop") action _drop_2() {
        standard_metadata.egress_spec = 9w511;
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
    @name("ingress.set_heavy_hitter_count") action set_heavy_hitter_count() {
        hash<bit<16>, bit<16>, tuple_0, bit<32>>(meta._custom_metadata_hash_val11, HashAlgorithm.csum16, 16w0, { hdr.ipv4.srcAddr, hdr.ipv4.dstAddr, hdr.ipv4.protocol, hdr.tcp.srcPort, hdr.tcp.dstPort }, 32w16);
        heavy_hitter_counter1_0.read(meta._custom_metadata_count_val13, (bit<32>)meta._custom_metadata_hash_val11);
        meta._custom_metadata_count_val13 = meta._custom_metadata_count_val13 + 16w1;
        heavy_hitter_counter1_0.write((bit<32>)meta._custom_metadata_hash_val11, meta._custom_metadata_count_val13);
        hash<bit<16>, bit<16>, tuple_0, bit<32>>(meta._custom_metadata_hash_val22, HashAlgorithm.crc16, 16w0, { hdr.ipv4.srcAddr, hdr.ipv4.dstAddr, hdr.ipv4.protocol, hdr.tcp.srcPort, hdr.tcp.dstPort }, 32w16);
        heavy_hitter_counter2_0.read(meta._custom_metadata_count_val24, (bit<32>)meta._custom_metadata_hash_val22);
        meta._custom_metadata_count_val24 = meta._custom_metadata_count_val24 + 16w1;
        heavy_hitter_counter2_0.write((bit<32>)meta._custom_metadata_hash_val22, meta._custom_metadata_count_val24);
    }
    @name("ingress.drop_heavy_hitter_table") table drop_heavy_hitter_table_0 {
        actions = {
            _drop_2();
            @defaultonly NoAction_1();
        }
        size = 1;
        default_action = NoAction_1();
    }
    @name("ingress.forward") table forward_0 {
        actions = {
            set_dmac();
            _drop_5();
            @defaultonly NoAction_7();
        }
        key = {
            meta._custom_metadata_nhop_ipv40: exact @name("meta.custom_metadata.nhop_ipv4") ;
        }
        size = 512;
        default_action = NoAction_7();
    }
    @name("ingress.ipv4_lpm") table ipv4_lpm_0 {
        actions = {
            set_nhop();
            _drop_6();
            @defaultonly NoAction_8();
        }
        key = {
            hdr.ipv4.dstAddr: lpm @name("hdr.ipv4.dstAddr") ;
        }
        size = 1024;
        default_action = NoAction_8();
    }
    @name("ingress.set_heavy_hitter_count_table") table set_heavy_hitter_count_table_0 {
        actions = {
            set_heavy_hitter_count();
            @defaultonly NoAction_9();
        }
        size = 1;
        default_action = NoAction_9();
    }
    apply {
        set_heavy_hitter_count_table_0.apply();
        if (meta._custom_metadata_count_val13 > 16w100 && meta._custom_metadata_count_val24 > 16w100)  {
            drop_heavy_hitter_table_0.apply();
        } 
        else {
            ipv4_lpm_0.apply();
            forward_0.apply();
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
        verify_checksum<tuple_1, bit<16>>(true, { hdr.ipv4.version, hdr.ipv4.ihl, hdr.ipv4.diffserv, hdr.ipv4.totalLen, hdr.ipv4.identification, hdr.ipv4.flags, hdr.ipv4.fragOffset, hdr.ipv4.ttl, hdr.ipv4.protocol, hdr.ipv4.srcAddr, hdr.ipv4.dstAddr }, hdr.ipv4.hdrChecksum, HashAlgorithm.csum16);
    }
}

control computeChecksum(inout headers hdr, inout metadata meta) {
    apply {
        update_checksum<tuple_1, bit<16>>(true, { hdr.ipv4.version, hdr.ipv4.ihl, hdr.ipv4.diffserv, hdr.ipv4.totalLen, hdr.ipv4.identification, hdr.ipv4.flags, hdr.ipv4.fragOffset, hdr.ipv4.ttl, hdr.ipv4.protocol, hdr.ipv4.srcAddr, hdr.ipv4.dstAddr }, hdr.ipv4.hdrChecksum, HashAlgorithm.csum16);
    }
}

V1Switch<headers, metadata>(ParserImpl(), verifyChecksum(), ingress(), egress(), computeChecksum(), DeparserImpl()) main;

void copy_field_list(in metadata from, inout metadata to, in standard_metadata_t smfrom, inout standard_metadata_t smto, in bit<16> discriminator) {
    ;
}
