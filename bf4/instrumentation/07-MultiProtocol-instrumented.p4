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
    bit<1> drop;
    bit<9> egress_port;
    bit<4> packet_type;
}

header ethernet_t {
    bit<48> dstAddr;
    bit<48> srcAddr;
    bit<16> etherType;
}

header icmp_t {
    bit<16> typeCode;
    bit<16> hdrChecksum;
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

header tcp_t {
    bit<16> srcPort;
    bit<16> dstPort;
    bit<32> seqNo;
    bit<32> ackNo;
    bit<4>  dataOffset;
    bit<4>  res;
    bit<8>  flags;
    bit<16> window;
    bit<16> checksum;
    bit<16> urgentPtr;
}

header udp_t {
    bit<16> srcPort;
    bit<16> dstPort;
    bit<16> length_;
    bit<16> checksum;
}

header vlan_tag_t {
    bit<3>  pcp;
    bit<1>  cfi;
    bit<12> vid;
    bit<16> etherType;
}

struct metadata {
    bit<1> _ing_metadata_drop0;
    bit<9> _ing_metadata_egress_port1;
    bit<4> _ing_metadata_packet_type2;
}

struct headers {
    @name(".ethernet") 
    ethernet_t ethernet;
    @name(".icmp") 
    icmp_t     icmp;
    @name(".ipv4") 
    ipv4_t     ipv4;
    @name(".ipv6") 
    ipv6_t     ipv6;
    @name(".tcp") 
    tcp_t      tcp;
    @name(".udp") 
    udp_t      udp;
    @name(".vlan_tag") 
    vlan_tag_t vlan_tag;
}

parser ParserImpl(packet_in packet, out headers hdr, inout metadata meta, inout standard_metadata_t standard_metadata) {
    @name(".parse_icmp") state parse_icmp {
        packet.extract<icmp_t>(hdr.icmp);
        transition accept;
    }
    @name(".parse_ipv4") state parse_ipv4 {
        packet.extract<ipv4_t>(hdr.ipv4);
        transition select(hdr.ipv4.fragOffset, hdr.ipv4.ihl, hdr.ipv4.protocol) {
            (13w0x0 &&& 13w0x0, 4w0x5 &&& 4w0xf, 8w0x1 &&& 8w0xff): parse_icmp;
            (13w0x0 &&& 13w0x0, 4w0x5 &&& 4w0xf, 8w0x6 &&& 8w0xff): parse_tcp;
            (13w0x0 &&& 13w0x0, 4w0x5 &&& 4w0xf, 8w0x11 &&& 8w0xff): parse_udp;
            default: accept;
        }
    }
    @name(".parse_ipv6") state parse_ipv6 {
        packet.extract<ipv6_t>(hdr.ipv6);
        transition select(hdr.ipv6.nextHdr) {
            8w0x1: parse_icmp;
            8w0x6: parse_tcp;
            8w0x11: parse_udp;
            default: accept;
        }
    }
    @name(".parse_tcp") state parse_tcp {
        packet.extract<tcp_t>(hdr.tcp);
        transition accept;
    }
    @name(".parse_udp") state parse_udp {
        packet.extract<udp_t>(hdr.udp);
        transition accept;
    }
    @name(".parse_vlan_tag") state parse_vlan_tag {
        packet.extract<vlan_tag_t>(hdr.vlan_tag);
        transition select(hdr.vlan_tag.etherType) {
            16w0x800: parse_ipv4;
            16w0x86dd: parse_ipv6;
            default: accept;
        }
    }
    @name(".start") state start {
        packet.extract<ethernet_t>(hdr.ethernet);
        transition select(hdr.ethernet.etherType) {
            16w0x8100: parse_vlan_tag;
            16w0x9100: parse_vlan_tag;
            16w0x800: parse_ipv4;
            16w0x86dd: parse_ipv6;
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
    @name(".NoAction") action NoAction_9() {
    }
    @name(".NoAction") action NoAction_10() {
    }
    @name(".NoAction") action NoAction_11() {
    }
    @name(".NoAction") action NoAction_12() {
    }
    @name(".NoAction") action NoAction_13() {
    }
    @name(".NoAction") action NoAction_14() {
    }
    @name(".NoAction") action NoAction_15() {
    }
    @name(".l2_packet") action l2_packet() {
        meta._ing_metadata_packet_type2 = 4w0;
    }
    @name(".ipv4_packet") action ipv4_packet() {
        meta._ing_metadata_packet_type2 = 4w1;
    }
    @name(".ipv6_packet") action ipv6_packet() {
        meta._ing_metadata_packet_type2 = 4w2;
    }
    @name(".mpls_packet") action mpls_packet() {
        meta._ing_metadata_packet_type2 = 4w3;
    }
    @name(".mim_packet") action mim_packet() {
        meta._ing_metadata_packet_type2 = 4w4;
    }
    @name(".nop") action nop() {
    }
    @name(".nop") action nop_6() {
    }
    @name(".nop") action nop_7() {
    }
    @name(".nop") action nop_8() {
    }
    @name(".nop") action nop_9() {
    }
    @name(".nop") action nop_10() {
    }
    @name("._drop") action _drop() {
        meta._ing_metadata_drop0 = 1w1;
    }
    @name("._drop") action _drop_3() {
        meta._ing_metadata_drop0 = 1w1;
    }
    @name("._drop") action _drop_4() {
        meta._ing_metadata_drop0 = 1w1;
    }
    @name(".set_egress_port") action set_egress_port(bit<9> egress_port) {
        meta._ing_metadata_egress_port1 = egress_port;
    }
    @name(".set_egress_port") action set_egress_port_3(bit<9> egress_port) {
        meta._ing_metadata_egress_port1 = egress_port;
    }
    @name(".set_egress_port") action set_egress_port_4(bit<9> egress_port) {
        meta._ing_metadata_egress_port1 = egress_port;
    }
    @name(".discard") action discard() {
        {
            standard_metadata.egress_spec = 9w511;
            __track_egress_spec = true;
        }
    }
    @name(".send_packet") action send_packet() {
        {
            standard_metadata.egress_spec = meta._ing_metadata_egress_port1;
            __track_egress_spec = true;
        }
    }
    @name(".ethertype_match") @instrument_keys() table ethertype_match {
        actions = {
            l2_packet();
            ipv4_packet();
            ipv6_packet();
            mpls_packet();
            mim_packet();
            @defaultonly NoAction_0();
        }
        key = {
            hdr.ethernet.etherType: exact @name("ethernet.etherType") ;
        }
        default_action = NoAction_0();
    }
    @name(".icmp_check") @instrument_keys() table icmp_check {
        actions = {
            nop();
            _drop();
            @defaultonly NoAction_9();
        }
        key = {
            hdr.icmp.typeCode: exact @name("icmp.typeCode") ;
        }
        default_action = NoAction_9();
    }
    @name(".ipv4_match") @instrument_keys() table ipv4_match {
        actions = {
            nop_6();
            set_egress_port();
            @defaultonly NoAction_10();
        }
        key = {
            hdr.ipv4.dstAddr: exact @name("ipv4.dstAddr") ;
        }
        default_action = NoAction_10();
    }
    @name(".ipv6_match") @instrument_keys() table ipv6_match {
        actions = {
            nop_7();
            set_egress_port_3();
            @defaultonly NoAction_11();
        }
        key = {
            hdr.ipv6.dstAddr: exact @name("ipv6.dstAddr") ;
        }
        default_action = NoAction_11();
    }
    @name(".l2_match") @instrument_keys() table l2_match {
        actions = {
            nop_8();
            set_egress_port_4();
            @defaultonly NoAction_12();
        }
        key = {
            hdr.ethernet.dstAddr: exact @name("ethernet.dstAddr") ;
        }
        default_action = NoAction_12();
    }
    @name(".set_egress") @instrument_keys() table set_egress {
        actions = {
            discard();
            send_packet();
            @defaultonly NoAction_13();
        }
        key = {
            meta._ing_metadata_drop0: exact @name("ing_metadata.drop") ;
        }
        default_action = NoAction_13();
    }
    @name(".tcp_check") @instrument_keys() table tcp_check {
        actions = {
            nop_9();
            _drop_3();
            @defaultonly NoAction_14();
        }
        key = {
            hdr.tcp.dstPort: exact @name("tcp.dstPort") ;
        }
        default_action = NoAction_14();
    }
    @name(".udp_check") @instrument_keys() table udp_check {
        actions = {
            nop_10();
            _drop_4();
            @defaultonly NoAction_15();
        }
        key = {
            hdr.udp.dstPort: exact @name("udp.dstPort") ;
        }
        default_action = NoAction_15();
    }
    apply {
        __track_egress_spec = false;
        switch (ethertype_match.apply().action_run) {
            ipv4_packet: {
                ipv4_match.apply();
            }
            mpls_packet: 
            ipv6_packet: {
                ipv6_match.apply();
            }
            default: {
                l2_match.apply();
            }
        }

        if (hdr.tcp.isValid())  {
            tcp_check.apply();
        } 
        else  {
            if (hdr.udp.isValid())  {
                udp_check.apply();
            } 
            else  {
                if (hdr.icmp.isValid())  {
                    icmp_check.apply();
                } 
            }
        }
        set_egress.apply();
        if (!__track_egress_spec)  {
            bug();
        } 
    }
}

control DeparserImpl(packet_out packet, in headers hdr) {
    apply {
        packet.emit<ethernet_t>(hdr.ethernet);
        packet.emit<vlan_tag_t>(hdr.vlan_tag);
        packet.emit<ipv6_t>(hdr.ipv6);
        packet.emit<ipv4_t>(hdr.ipv4);
        packet.emit<udp_t>(hdr.udp);
        packet.emit<tcp_t>(hdr.tcp);
        packet.emit<icmp_t>(hdr.icmp);
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
}
