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
    apply {
        send_frame.apply();
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
    bool __track_egress_spec;
    @name(".NoAction") action NoAction_1() {
    }
    @name(".NoAction") action NoAction_7() {
    }
    @name(".NoAction") action NoAction_8() {
    }
    @name(".NoAction") action NoAction_9() {
    }
    @name("ingress.heavy_hitter_counter1") register<bit<16>>(32w16) heavy_hitter_counter1;
    @name("ingress.heavy_hitter_counter2") register<bit<16>>(32w16) heavy_hitter_counter2;
    @name("ingress._drop") action _drop_2() {
        {
            standard_metadata.egress_spec = 9w511;
            __track_egress_spec = true;
        }
    }
    @name("ingress._drop") action _drop_5() {
        {
            standard_metadata.egress_spec = 9w511;
            __track_egress_spec = true;
        }
    }
    @name("ingress._drop") action _drop_6() {
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
    @name("ingress.set_heavy_hitter_count") action set_heavy_hitter_count() {
        hash<bit<16>, bit<16>, tuple_0, bit<32>>(meta._custom_metadata_hash_val11, HashAlgorithm.csum16, 16w0, tuple_0 {field = hdr.ipv4.srcAddr,field_0 = hdr.ipv4.dstAddr,field_1 = hdr.ipv4.protocol,field_2 = hdr.tcp.srcPort,field_3 = hdr.tcp.dstPort}, 32w16);
        {
            if (!((bit<32>)meta._custom_metadata_hash_val11 < 32w16))  {
                bug();
            } 
            heavy_hitter_counter1.read(meta._custom_metadata_count_val13, (bit<32>)meta._custom_metadata_hash_val11);
        }
        meta._custom_metadata_count_val13 = meta._custom_metadata_count_val13 + 16w1;
        {
            if (!((bit<32>)meta._custom_metadata_hash_val11 < 32w16))  {
                bug();
            } 
            heavy_hitter_counter1.write((bit<32>)meta._custom_metadata_hash_val11, meta._custom_metadata_count_val13);
        }
        hash<bit<16>, bit<16>, tuple_0, bit<32>>(meta._custom_metadata_hash_val22, HashAlgorithm.crc16, 16w0, tuple_0 {field = hdr.ipv4.srcAddr,field_0 = hdr.ipv4.dstAddr,field_1 = hdr.ipv4.protocol,field_2 = hdr.tcp.srcPort,field_3 = hdr.tcp.dstPort}, 32w16);
        {
            if (!((bit<32>)meta._custom_metadata_hash_val22 < 32w16))  {
                bug();
            } 
            heavy_hitter_counter2.read(meta._custom_metadata_count_val24, (bit<32>)meta._custom_metadata_hash_val22);
        }
        meta._custom_metadata_count_val24 = meta._custom_metadata_count_val24 + 16w1;
        {
            if (!((bit<32>)meta._custom_metadata_hash_val22 < 32w16))  {
                bug();
            } 
            heavy_hitter_counter2.write((bit<32>)meta._custom_metadata_hash_val22, meta._custom_metadata_count_val24);
        }
    }
    @name("ingress.drop_heavy_hitter_table") @instrument_keys() table drop_heavy_hitter_table {
        actions = {
            _drop_2();
            @defaultonly NoAction_1();
        }
        size = 1;
        default_action = NoAction_1();
    }
    @name("ingress.forward") @instrument_keys() table forward {
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
    @name("ingress.ipv4_lpm") @instrument_keys() table ipv4_lpm {
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
    @name("ingress.set_heavy_hitter_count_table") @instrument_keys() table set_heavy_hitter_count_table {
        actions = {
            set_heavy_hitter_count();
            @defaultonly NoAction_9();
        }
        size = 1;
        default_action = NoAction_9();
    }
    apply {
        __track_egress_spec = false;
        set_heavy_hitter_count_table.apply();
        if (meta._custom_metadata_count_val13 > 16w100 && meta._custom_metadata_count_val24 > 16w100)  {
            drop_heavy_hitter_table.apply();
        } 
        else {
            ipv4_lpm.apply();
            forward.apply();
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
    }
}

control computeChecksum(inout headers hdr, inout metadata meta) {
    apply {
    }
}

V1Switch<headers, metadata>(ParserImpl(), verifyChecksum(), ingress(), egress(), computeChecksum(), DeparserImpl()) main;

void copy_field_list(in metadata from, inout metadata to, in standard_metadata_t smfrom, inout standard_metadata_t smto, in bit<16> discriminator) {
}
