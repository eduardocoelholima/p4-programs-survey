enum flow_def_setter_0__action_type_t {
    set_iface,
    drop_1,
    NoAction_0
}

struct flow_def_setter_0 {
    bool                             hit;
    bool                             reach;
    flow_def_setter_0__action_type_t action_run;
    bit<16>                          set_iface__router_interface_value;
    @matchKind("exact") 
    bit<48>                          key_setter_0_hdr_ethernet_dstAddr;
}

@controlled() extern flow_def_setter_0 query_setter_0(@matchKind("exact") in bit<48> setter_0_hdr_ethernet_dstAddr);
extern void end_setter_0();
enum flow_def_getter_0__action_type_t {
    fwd,
    drop_3
}

struct flow_def_getter_0 {
    bool                             hit;
    bool                             reach;
    flow_def_getter_0__action_type_t action_run;
    bit<9>                           fwd__port;
    @matchKind("exact") 
    bit<16>                          key_getter_0_meta_meta_router_interface_value;
}

@controlled() extern flow_def_getter_0 query_getter_0(@matchKind("exact") in bit<16> getter_0_meta_meta_router_interface_value);
extern void end_getter_0();
enum flow_def_allocator_0__action_type_t {
    allocated_1,
    unallocated
}

struct flow_def_allocator_0 {
    bool                                hit;
    bool                                reach;
    flow_def_allocator_0__action_type_t action_run;
    @matchKind("exact") 
    bit<16>                             key_allocator_0_meta_meta_router_interface_value;
}

@controlled() extern flow_def_allocator_0 query_allocator_0(@matchKind("exact") in bit<16> allocator_0_meta_meta_router_interface_value);
extern void end_allocator_0();
extern void key_match(in bool condition);
extern void angelic_assert(in bool condition);
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
        transition reject;
    }
}

control ingress(inout headers hdr, inout metadata meta, inout standard_metadata_t standard_metadata) {
    bool __track_egress_spec_0;
    apply {
        meta._ghost_iface_set1 = 1w0;
        meta._ghost_allocated2 = 1w0;
        meta._ghost_forwarded3 = 1w0;
        {
            flow_def_setter_0 setter;
            setter = query_setter_0(hdr.ethernet.dstAddr);
            if (setter.hit) {
                key_match(hdr.ethernet.dstAddr == setter.key_setter_0_hdr_ethernet_dstAddr);
                if (!hdr.ethernet.isValid())  {
                    bug();
                } 
            }
            if (setter.action_run == flow_def_setter_0__action_type_t.NoAction_0) {
            }
            else  {
                if (setter.action_run == flow_def_setter_0__action_type_t.drop_1) {
                    angelic_assert(true);
                    {
                    }
                }
                else  {
                    if (setter.action_run == flow_def_setter_0__action_type_t.set_iface) {
                        angelic_assert(true);
                        {
                            meta._meta_router_interface_value0 = setter.set_iface__router_interface_value;
                            meta._ghost_iface_set1 = 1w1;
                        }
                    }
                    else  {
                        ;
                    }
                }
            }
            end_setter_0();
        }
        {
            flow_def_allocator_0 allocator;
            allocator = query_allocator_0(meta._meta_router_interface_value0);
            if (allocator.hit) {
                key_match(meta._meta_router_interface_value0 == allocator.key_allocator_0_meta_meta_router_interface_value);
            }
            if (allocator.action_run == flow_def_allocator_0__action_type_t.unallocated) {
            }
            else  {
                if (allocator.action_run == flow_def_allocator_0__action_type_t.allocated_1) {
                    angelic_assert(true);
                    {
                        meta._ghost_allocated2 = 1w1;
                    }
                }
                else  {
                    ;
                }
            }
            end_allocator_0();
        }
        {
            flow_def_getter_0 getter;
            getter = query_getter_0(meta._meta_router_interface_value0);
            if (getter.hit) {
                key_match(meta._meta_router_interface_value0 == getter.key_getter_0_meta_meta_router_interface_value);
            }
            if (getter.action_run == flow_def_getter_0__action_type_t.drop_3) {
            }
            else  {
                if (getter.action_run == flow_def_getter_0__action_type_t.fwd) {
                    angelic_assert(true);
                    {
                        meta._ghost_forwarded3 = 1w1;
                    }
                }
                else  {
                    ;
                }
            }
            end_getter_0();
        }
        if (!(meta._ghost_iface_set1 == 1w0 || meta._ghost_allocated2 == 1w1))  {
            bug();
        } 
        if (!(meta._ghost_forwarded3 == 1w0 || meta._ghost_allocated2 == 1w1))  {
            bug();
        } 
        standard_metadata.egress_spec = 9w511;
        __track_egress_spec_0 = true;
        if (!__track_egress_spec_0)  {
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
