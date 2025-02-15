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

struct ingress_metadata_t {
    bit<32> flow_ipg;
    bit<13> flowlet_map_index;
    bit<16> flowlet_id;
    bit<32> flowlet_lasttime;
    bit<14> ecmp_offset;
    bit<32> nhop_ipv4;
}

struct intrinsic_metadata_t {
    bit<48> ingress_global_timestamp;
    bit<32> lf_field_list;
    bit<16> mcast_grp;
    bit<16> egress_rid;
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
    bit<32> _ingress_metadata_flow_ipg0;
    bit<13> _ingress_metadata_flowlet_map_index1;
    bit<16> _ingress_metadata_flowlet_id2;
    bit<32> _ingress_metadata_flowlet_lasttime3;
    bit<14> _ingress_metadata_ecmp_offset4;
    bit<32> _ingress_metadata_nhop_ipv45;
    bit<48> _intrinsic_metadata_ingress_global_timestamp6;
    bit<32> _intrinsic_metadata_lf_field_list7;
    bit<16> _intrinsic_metadata_mcast_grp8;
    bit<16> _intrinsic_metadata_egress_rid9;
}

struct headers {
    @name(".ethernet") 
    ethernet_t ethernet;
    @name(".ipv4") 
    ipv4_t     ipv4;
    @name(".tcp") 
    tcp_t      tcp;
}

parser ParserImpl(packet_in packet, out headers hdr, inout metadata meta, inout standard_metadata_t standard_metadata) {
    @name(".parse_ethernet") state parse_ethernet {
        packet.extract<ethernet_t>(hdr.ethernet);
        transition select(hdr.ethernet.etherType) {
            16w0x800: parse_ipv4;
            default: accept;
        }
    }
    @name(".parse_ipv4") state parse_ipv4 {
        packet.extract<ipv4_t>(hdr.ipv4);
        transition select(hdr.ipv4.protocol) {
            8w6: parse_tcp;
            default: accept;
        }
    }
    @name(".parse_tcp") state parse_tcp {
        packet.extract<tcp_t>(hdr.tcp);
        transition accept;
    }
    @name(".start") state start {
        transition parse_ethernet;
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
    bit<16> field_4;
}

struct tuple_1 {
    bit<32> field_5;
    bit<32> field_6;
    bit<8>  field_7;
    bit<16> field_8;
    bit<16> field_9;
}

control ingress(inout headers hdr, inout metadata meta, inout standard_metadata_t standard_metadata) {
    bool __track_egress_spec;
    @name(".NoAction") action NoAction_1() {
    }
    @name(".NoAction") action NoAction_8() {
    }
    @name(".NoAction") action NoAction_9() {
    }
    @name(".NoAction") action NoAction_10() {
    }
    @name(".NoAction") action NoAction_11() {
    }
    @name("ingress.flowlet_id") register<bit<16>>(32w8192) flowlet_id_1;
    @name("ingress.flowlet_lasttime") register<bit<32>>(32w8192) flowlet_lasttime_1;
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
    @name("ingress.set_ecmp_select") action set_ecmp_select(bit<8> ecmp_base, bit<8> ecmp_count) {
        hash<bit<14>, bit<10>, tuple_0, bit<20>>(meta._ingress_metadata_ecmp_offset4, HashAlgorithm.crc16, (bit<10>)ecmp_base, tuple_0 {field = hdr.ipv4.srcAddr,field_0 = hdr.ipv4.dstAddr,field_1 = hdr.ipv4.protocol,field_2 = hdr.tcp.srcPort,field_3 = hdr.tcp.dstPort,field_4 = meta._ingress_metadata_flowlet_id2}, (bit<20>)ecmp_count);
    }
    @name("ingress.set_nhop") action set_nhop(bit<32> nhop_ipv4, bit<9> port) {
        meta._ingress_metadata_nhop_ipv45 = nhop_ipv4;
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
    @name("ingress.lookup_flowlet_map") action lookup_flowlet_map() {
        hash<bit<13>, bit<13>, tuple_1, bit<26>>(meta._ingress_metadata_flowlet_map_index1, HashAlgorithm.crc16, 13w0, tuple_1 {field_5 = hdr.ipv4.srcAddr,field_6 = hdr.ipv4.dstAddr,field_7 = hdr.ipv4.protocol,field_8 = hdr.tcp.srcPort,field_9 = hdr.tcp.dstPort}, 26w13);
        {
            if (!((bit<32>)meta._ingress_metadata_flowlet_map_index1 < 32w8192))  {
                bug();
            } 
            flowlet_id_1.read(meta._ingress_metadata_flowlet_id2, (bit<32>)meta._ingress_metadata_flowlet_map_index1);
        }
        {
            if (!((bit<32>)meta._ingress_metadata_flowlet_map_index1 < 32w8192))  {
                bug();
            } 
            flowlet_lasttime_1.read(meta._ingress_metadata_flowlet_lasttime3, (bit<32>)meta._ingress_metadata_flowlet_map_index1);
        }
        meta._ingress_metadata_flow_ipg0 = (bit<32>)meta._intrinsic_metadata_ingress_global_timestamp6 - meta._ingress_metadata_flowlet_lasttime3;
        {
            if (!((bit<32>)meta._ingress_metadata_flowlet_map_index1 < 32w8192))  {
                bug();
            } 
            flowlet_lasttime_1.write((bit<32>)meta._ingress_metadata_flowlet_map_index1, (bit<32>)meta._intrinsic_metadata_ingress_global_timestamp6);
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
    @name("ingress.update_flowlet_id") action update_flowlet_id() {
        meta._ingress_metadata_flowlet_id2 = meta._ingress_metadata_flowlet_id2 + 16w1;
        {
            if (!((bit<32>)meta._ingress_metadata_flowlet_map_index1 < 32w8192))  {
                bug();
            } 
            flowlet_id_1.write((bit<32>)meta._ingress_metadata_flowlet_map_index1, meta._ingress_metadata_flowlet_id2);
        }
    }
    @name("ingress.ecmp_group") @instrument_keys() table ecmp_group {
        actions = {
            _drop_2();
            set_ecmp_select();
            @defaultonly NoAction_1();
        }
        key = {
            hdr.ipv4.dstAddr: lpm @name("ipv4.dstAddr") ;
        }
        size = 1024;
        default_action = NoAction_1();
    }
    @name("ingress.ecmp_nhop") @instrument_keys() table ecmp_nhop {
        actions = {
            _drop_5();
            set_nhop();
            @defaultonly NoAction_8();
        }
        key = {
            meta._ingress_metadata_ecmp_offset4: exact @name("ingress_metadata.ecmp_offset") ;
        }
        size = 16384;
        default_action = NoAction_8();
    }
    @name("ingress.flowlet") @instrument_keys() table flowlet {
        actions = {
            lookup_flowlet_map();
            @defaultonly NoAction_9();
        }
        default_action = NoAction_9();
    }
    @name("ingress.forward") @instrument_keys() table forward {
        actions = {
            set_dmac();
            _drop_6();
            @defaultonly NoAction_10();
        }
        key = {
            meta._ingress_metadata_nhop_ipv45: exact @name("ingress_metadata.nhop_ipv4") ;
        }
        size = 512;
        default_action = NoAction_10();
    }
    @name("ingress.new_flowlet") @instrument_keys() table new_flowlet {
        actions = {
            update_flowlet_id();
            @defaultonly NoAction_11();
        }
        default_action = NoAction_11();
    }
    apply {
        __track_egress_spec = false;
        flowlet.apply();
        if (meta._ingress_metadata_flow_ipg0 > 32w50000)  {
            new_flowlet.apply();
        } 
        ecmp_group.apply();
        ecmp_nhop.apply();
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

struct tuple_2 {
    bit<4>  field_10;
    bit<4>  field_11;
    bit<8>  field_12;
    bit<16> field_13;
    bit<16> field_14;
    bit<3>  field_15;
    bit<13> field_16;
    bit<8>  field_17;
    bit<8>  field_18;
    bit<32> field_19;
    bit<32> field_20;
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
