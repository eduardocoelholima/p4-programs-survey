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
    bit<32> key_1;
    @name(".NoAction") action NoAction_0() {
    }
    @name(".NoAction") action NoAction_1() {
    }
    @name(".NoAction") action NoAction_9() {
    }
    @name(".NoAction") action NoAction_10() {
    }
    @name("egress.rewrite_mac") action rewrite_mac(bit<48> smac) {
        {
            if (hdr.ethernet.isValid())  {
                hdr.ethernet.srcAddr = smac;
            } 
            else  {
                bug();
            }
        }
    }
    @name("egress._drop") action _drop() {
        standard_metadata.egress_spec = 9w511;
    }
    @name("egress._drop") action _drop_2() {
        standard_metadata.egress_spec = 9w511;
    }
    @name("egress._drop") action _drop_7() {
        standard_metadata.egress_spec = 9w511;
    }
    @name("egress.validate_H1") action validate_H1() {
        hdr.ipv4.setValid();
    }
    @name("egress.validate_H2") action validate_H2() {
        hdr.ethernet.setValid();
    }
    @name("egress.use_H12") action use_H12() {
        {
            if (hdr.ipv4.isValid() && hdr.ipv4.isValid())  {
                hdr.ipv4.srcAddr = hdr.ipv4.dstAddr;
            } 
            else  {
                bug();
            }
        }
        {
            if (hdr.ethernet.isValid() && hdr.ethernet.isValid())  {
                hdr.ethernet.srcAddr = hdr.ethernet.dstAddr;
            } 
            else  {
                bug();
            }
        }
    }
    @name("egress.send_frame") @instrument_keys() table send_frame {
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
    @name("egress.t1") @instrument_keys() table t1 {
        key = {
            hdr.ipv4.srcAddr: exact @name("hdr.ipv4.srcAddr") ;
        }
        actions = {
            validate_H1();
            _drop_2();
            @defaultonly NoAction_1();
        }
        default_action = NoAction_1();
    }
    @name("egress.t2") @instrument_keys() table t2 {
        key = {
            hdr.ipv4.dstAddr: exact @name("hdr.ipv4.dstAddr") ;
        }
        actions = {
            validate_H2();
            _drop_7();
            @defaultonly NoAction_9();
        }
        default_action = NoAction_9();
    }
    @name("egress.t3") @instrument_keys() table t3 {
        key = {
            key_1       : exact @name("header1") ;
            hdr.ipv4.ttl: exact @name("hdr.ipv4.ttl") ;
        }
        actions = {
            use_H12();
            @defaultonly NoAction_10();
        }
        default_action = NoAction_10();
    }
    apply {
        hdr.ipv4.setInvalid();
        hdr.ethernet.setInvalid();
        t1.apply();
        t2.apply();
        {
            if (hdr.ipv4.isValid() && hdr.ipv4.isValid())  {
                key_1 = hdr.ipv4.srcAddr + hdr.ipv4.dstAddr;
            } 
            else  {
                bug();
            }
        }
        t3.apply();
        send_frame.apply();
    }
}

control ingress(inout headers hdr, inout metadata meta, inout standard_metadata_t standard_metadata) {
    bool __track_egress_spec;
    @name(".NoAction") action NoAction_11() {
    }
    @name(".NoAction") action NoAction_12() {
    }
    @name(".NoAction") action NoAction_13() {
    }
    @name("ingress.ip_src_counter") counter(32w1024, CounterType.packets) ip_src_counter;
    @name("ingress.count_action") action count_action(bit<32> idx) {
        {
            if (!(idx < 32w1024))  {
                bug();
            } 
            ip_src_counter.count(idx);
        }
    }
    @name("ingress._drop") action _drop_8() {
        {
            standard_metadata.egress_spec = 9w511;
            __track_egress_spec = true;
        }
    }
    @name("ingress._drop") action _drop_9() {
        {
            standard_metadata.egress_spec = 9w511;
            __track_egress_spec = true;
        }
    }
    @name("ingress._drop") action _drop_10() {
        {
            standard_metadata.egress_spec = 9w511;
            __track_egress_spec = true;
        }
    }
    @name("ingress.set_dmac") action set_dmac(bit<48> dmac) {
        {
            if (hdr.ethernet.isValid())  {
                hdr.ethernet.dstAddr = dmac;
            } 
            else  {
                bug();
            }
        }
    }
    @name("ingress.set_nhop") action set_nhop(bit<32> nhop_ipv4, bit<9> port) {
        meta._custom_metadata_nhop_ipv40 = nhop_ipv4;
        {
            standard_metadata.egress_spec = port;
            __track_egress_spec = true;
        }
        {
            if (hdr.ipv4.isValid() && hdr.ipv4.isValid())  {
                hdr.ipv4.ttl = hdr.ipv4.ttl + 8w255;
            } 
            else  {
                bug();
            }
        }
    }
    @name("ingress.count_table") @instrument_keys() table count_table {
        actions = {
            count_action();
            _drop_8();
            @defaultonly NoAction_11();
        }
        key = {
            hdr.ipv4.srcAddr: lpm @name("hdr.ipv4.srcAddr") ;
        }
        size = 1024;
        default_action = NoAction_11();
    }
    @name("ingress.forward") @instrument_keys() table forward {
        actions = {
            set_dmac();
            _drop_9();
            @defaultonly NoAction_12();
        }
        key = {
            meta._custom_metadata_nhop_ipv40: exact @name("meta.custom_metadata.nhop_ipv4") ;
        }
        size = 512;
        default_action = NoAction_12();
    }
    @name("ingress.ipv4_lpm") @instrument_keys() table ipv4_lpm {
        actions = {
            set_nhop();
            _drop_10();
            @defaultonly NoAction_13();
        }
        key = {
            hdr.ipv4.dstAddr: lpm @name("hdr.ipv4.dstAddr") ;
        }
        size = 1024;
        default_action = NoAction_13();
    }
    apply {
        __track_egress_spec = false;
        count_table.apply();
        ipv4_lpm.apply();
        forward.apply();
        if (!__track_egress_spec)  {
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

control computeChecksum(inout headers hdr, inout metadata meta) {
    apply {
    }
}

V1Switch<headers, metadata>(ParserImpl(), verifyChecksum(), ingress(), egress(), computeChecksum(), DeparserImpl()) main;

void copy_field_list(in metadata from, inout metadata to, in standard_metadata_t smfrom, inout standard_metadata_t smto, in bit<16> discriminator) {
}
