extern H havoc<H>();
extern void key_match(in bool condition);
extern void assert(in bool condition);
extern void angelic_assert(in bool condition);
extern void assume(in bool condition);
extern void oob();
extern void dontCare();
extern void do_drop();
extern void bug();

#include <core.p4>

#include <v1model.p4>

struct ingress_metadata_t {
    bit<16> router_interface_value;
}

struct ghost_t {
    bit<1> iface_set;
    bit<1> allocated;
    bit<1> forwarded;
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
    bit<16> _meta_router_interface_value0;
    bit<1>  _ghost_iface_set1;
    bit<1>  _ghost_allocated2;
    bit<1>  _ghost_forwarded3;
}

struct headers {
    ethernet_t ethernet;
    icmp_t     icmp;
    ipv4_t     ipv4;
    ipv6_t     ipv6;
    tcp_t      tcp;
    udp_t      udp;
    vlan_tag_t vlan_tag;
}

parser ParserImpl(packet_in packet, out headers hdr, inout metadata meta, inout standard_metadata_t standard_metadata) {
    @name(".start") state start {
        packet.extract<ethernet_t>(hdr.ethernet);
        transition accept;
    }
}

control ingress(inout headers hdr, inout metadata meta, inout standard_metadata_t standard_metadata) {
    bool __track_egress_spec;
    @name(".NoAction") action NoAction_0() {
    }
    @name("ingress.allocated") action allocated_1() {
        meta._ghost_allocated2 = 1w1;
    }
    @name("ingress.unallocated") action unallocated() {
    }
    @name("ingress.drop_") action drop_1() {
    }
    @name("ingress.drop_") action drop_3() {
    }
    @name("ingress.fwd") action fwd(bit<9> port) {
        meta._ghost_forwarded3 = 1w1;
    }
    @name("ingress.set_iface") action set_iface(bit<16> router_interface_value) {
        meta._meta_router_interface_value0 = router_interface_value;
        meta._ghost_iface_set1 = 1w1;
    }
    @name("ingress.setter") @instrument_keys() table setter {
        key = {
            hdr.ethernet.dstAddr: exact @name("hdr.ethernet.dstAddr") ;
        }
        actions = {
            set_iface();
            drop_1();
            @defaultonly NoAction_0();
        }
        default_action = NoAction_0();
    }
    @name("ingress.allocator") @instrument_keys() table allocator {
        key = {
            meta._meta_router_interface_value0: exact @name("meta.meta.router_interface_value") ;
            meta._ghost_iface_set1            : exact @name("meta.ghost.iface_set") ;
        }
        actions = {
            allocated_1();
            @defaultonly unallocated();
        }
        const default_action = unallocated();
    }
    @name("ingress.getter") @instrument_keys() table getter {
        key = {
            meta._meta_router_interface_value0: exact @name("meta.meta.router_interface_value") ;
            meta._ghost_allocated2            : exact @name("meta.ghost.allocated") ;
        }
        actions = {
            fwd();
            @defaultonly drop_3();
        }
        const default_action = drop_3();
    }
    apply {
        __track_egress_spec = false;
        meta._ghost_iface_set1 = 1w0;
        meta._ghost_allocated2 = 1w0;
        meta._ghost_forwarded3 = 1w0;
        setter.apply();
        allocator.apply();
        getter.apply();
        if (!(meta._ghost_iface_set1 == 1w0 || meta._ghost_allocated2 == 1w1))  {
            bug();
        } 
        if (!(meta._ghost_forwarded3 == 1w0 || meta._ghost_allocated2 == 1w1))  {
            bug();
        } 
        {
            standard_metadata.egress_spec = 9w511;
            __track_egress_spec = true;
        }
        if (!__track_egress_spec)  {
            bug();
        } 
    }
}

control egress(inout headers hdr, inout metadata meta, inout standard_metadata_t standard_metadata) {
    apply {
    }
}

control DeparserImpl(packet_out packet, in headers hdr) {
    apply {
        packet.emit<ethernet_t>(hdr.ethernet);
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
