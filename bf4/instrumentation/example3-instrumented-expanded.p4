enum flow_def_t3_0__action_type_t {
    decrement_ttl3,
    _drop_4,
    NoAction_5
}

struct flow_def_t3_0 {
    bool                         hit;
    bool                         reach;
    flow_def_t3_0__action_type_t action_run;
    @matchKind("exact") 
    bit<16>                      key_t3_0_hdr_ethernet_etherType;
}

@controlled() extern flow_def_t3_0 query_t3_0(@matchKind("exact") in bit<16> t3_0_hdr_ethernet_etherType);
extern void end_t3_0();
enum flow_def_t2_0__action_type_t {
    validate_H3,
    decrement_ttl2,
    _drop_3,
    NoAction_4
}

struct flow_def_t2_0 {
    bool                         hit;
    bool                         reach;
    flow_def_t2_0__action_type_t action_run;
    @matchKind("exact") 
    bit<16>                      key_t2_0_hdr_ethernet_etherType;
}

@controlled() extern flow_def_t2_0 query_t2_0(@matchKind("exact") in bit<16> t2_0_hdr_ethernet_etherType);
extern void end_t2_0();
enum flow_def_t1_0__action_type_t {
    validate_H2,
    _drop,
    NoAction_0
}

struct flow_def_t1_0 {
    bool                         hit;
    bool                         reach;
    flow_def_t1_0__action_type_t action_run;
    @matchKind("exact") 
    bit<16>                      key_t1_0_hdr_ethernet_etherType;
}

@controlled() extern flow_def_t1_0 query_t1_0(@matchKind("exact") in bit<16> t1_0_hdr_ethernet_etherType);
extern void end_t1_0();
extern void key_match(in bool condition);
extern void angelic_assert(in bool condition);
extern void bug();

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
    ipv4_t     ipv4_3;
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
    bool __track_egress_spec_0;
    apply {
        {
            flow_def_t1_0 t1;
            t1 = query_t1_0(hdr.ethernet.etherType);
            if (t1.hit) {
                key_match(hdr.ethernet.etherType == t1.key_t1_0_hdr_ethernet_etherType);
                if (!hdr.ethernet.isValid())  {
                    bug();
                } 
            }
            if (t1.action_run == flow_def_t1_0__action_type_t.NoAction_0) {
            }
            else  {
                if (t1.action_run == flow_def_t1_0__action_type_t._drop) {
                    angelic_assert(true);
                    {
                    }
                }
                else  {
                    if (t1.action_run == flow_def_t1_0__action_type_t.validate_H2) {
                        angelic_assert(true);
                        {
                            hdr.ipv4_2.setValid();
                        }
                    }
                    else  {
                        ;
                    }
                }
            }
            end_t1_0();
        }
        {
            flow_def_t2_0 t2;
            t2 = query_t2_0(hdr.ethernet.etherType);
            if (t2.hit) {
                key_match(hdr.ethernet.etherType == t2.key_t2_0_hdr_ethernet_etherType);
                if (!hdr.ethernet.isValid())  {
                    bug();
                } 
            }
            if (t2.action_run == flow_def_t2_0__action_type_t.NoAction_4) {
            }
            else  {
                if (t2.action_run == flow_def_t2_0__action_type_t._drop_3) {
                    angelic_assert(true);
                    {
                    }
                }
                else  {
                    if (t2.action_run == flow_def_t2_0__action_type_t.decrement_ttl2) {
                        angelic_assert(true);
                        {
                            if (hdr.ipv4_2.isValid() && hdr.ipv4_2.isValid())  {
                                hdr.ipv4_2.ttl = hdr.ipv4_2.ttl + 8w255;
                            } 
                            else  {
                                bug();
                            }
                        }
                    }
                    else  {
                        if (t2.action_run == flow_def_t2_0__action_type_t.validate_H3) {
                            angelic_assert(true);
                            {
                                hdr.ipv4_3.setValid();
                            }
                        }
                        else  {
                            ;
                        }
                    }
                }
            }
            end_t2_0();
        }
        {
            flow_def_t3_0 t3;
            t3 = query_t3_0(hdr.ethernet.etherType);
            if (t3.hit) {
                key_match(hdr.ethernet.etherType == t3.key_t3_0_hdr_ethernet_etherType);
                if (!hdr.ethernet.isValid())  {
                    bug();
                } 
            }
            if (t3.action_run == flow_def_t3_0__action_type_t.NoAction_5) {
            }
            else  {
                if (t3.action_run == flow_def_t3_0__action_type_t._drop_4) {
                    angelic_assert(true);
                    {
                    }
                }
                else  {
                    if (t3.action_run == flow_def_t3_0__action_type_t.decrement_ttl3) {
                        angelic_assert(true);
                        {
                            if (hdr.ipv4_3.isValid() && hdr.ipv4_3.isValid())  {
                                hdr.ipv4_3.ttl = hdr.ipv4_3.ttl + 8w255;
                            } 
                            else  {
                                bug();
                            }
                        }
                    }
                    else  {
                        ;
                    }
                }
            }
            end_t3_0();
        }
        standard_metadata.egress_spec = 9w5;
        __track_egress_spec_0 = true;
        if (!__track_egress_spec_0)  {
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
