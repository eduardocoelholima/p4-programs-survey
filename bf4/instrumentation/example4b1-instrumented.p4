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
    ipv4_t     ipv4_2;
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
    apply {
    }
}

control ingress(inout headers hdr, inout metadata meta, inout standard_metadata_t standard_metadata) {
    bool __track_egress_spec;
    @name(".NoAction") action NoAction_0() {
    }
    @name(".NoAction") action NoAction_4() {
    }
    @name(".NoAction") action NoAction_5() {
    }
    @name("ingress._drop") action _drop() {
    }
    @name("ingress._drop") action _drop_3() {
    }
    @name("ingress._drop") action _drop_4() {
    }
    @name("ingress.set_ttl2") action set_ttl2(bit<8> newTtl) {
        {
            if (hdr.ipv4_2.isValid())  {
                hdr.ipv4_2.ttl = newTtl;
            } 
            else  {
                bug();
            }
        }
    }
    @name("ingress.copy_ip_src") action copy_ip_src() {
        {
            if (hdr.ipv4_2.isValid() && hdr.ipv4.isValid())  {
                hdr.ipv4.srcAddr = hdr.ipv4_2.srcAddr;
            } 
            else  {
                bug();
            }
        }
    }
    @name("ingress.use_H12") action use_H12() {
        {
            if (hdr.ipv4_2.isValid() && hdr.ipv4.isValid())  {
                hdr.ipv4.srcAddr = hdr.ipv4_2.srcAddr;
            } 
            else  {
                bug();
            }
        }
    }
    @name("ingress.t1") @instrument_keys() table t1 {
        key = {
            hdr.ipv4.isValid(): exact @name("hdr.ipv4.$valid$") ;
        }
        actions = {
            copy_ip_src();
            _drop();
            @defaultonly NoAction_0();
        }
        default_action = NoAction_0();
    }
    @name("ingress.t2") @instrument_keys() table t2 {
        key = {
            hdr.ipv4_2.isValid(): exact @name("hdr.ipv4_2.$valid$") ;
        }
        actions = {
            use_H12();
            _drop_3();
            @defaultonly NoAction_4();
        }
        default_action = NoAction_4();
    }
    @name("ingress.t3") @instrument_keys() table t3 {
        key = {
            hdr.ipv4.srcAddr: exact @name("hdr.ipv4.srcAddr") ;
        }
        actions = {
            set_ttl2();
            _drop_4();
            @defaultonly NoAction_5();
        }
        default_action = NoAction_5();
    }
    apply {
        __track_egress_spec = false;
        t1.apply();
        t2.apply();
        t3.apply();
        {
            standard_metadata.egress_spec = 9w5;
            __track_egress_spec = true;
        }
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
