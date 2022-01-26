enum flow_def_t2_0__action_type_t {
    use_0,
    drop_3,
    NoAction_3
}

struct flow_def_t2_0 {
    bool                         hit;
    bool                         reach;
    flow_def_t2_0__action_type_t action_run;
    @matchKind("exact") 
    bit<16>                      key_t2_0_ethernet_etherType;
}

@controlled() extern flow_def_t2_0 query_t2_0(@matchKind("exact") in bit<16> t2_0_ethernet_etherType);
extern void end_t2_0();
enum flow_def_t1_0__action_type_t {
    validate_0,
    drop_1,
    NoAction_0
}

struct flow_def_t1_0 {
    bool                         hit;
    bool                         reach;
    flow_def_t1_0__action_type_t action_run;
    @matchKind("exact") 
    bit<16>                      key_t1_0_ethernet_etherType;
}

@controlled() extern flow_def_t1_0 query_t1_0(@matchKind("exact") in bit<16> t1_0_ethernet_etherType);
extern void end_t1_0();
extern void key_match(in bool condition);
extern void angelic_assert(in bool condition);
extern void bug();

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

struct metadata {
    bit<1> _ing_metadata_drop0;
    bit<9> _ing_metadata_egress_port1;
    bit<4> _ing_metadata_packet_type2;
}

struct headers {
    @name(".ethernet") 
    ethernet_t ethernet;
    @name(".ipv4") 
    ipv4_t     ipv4;
    ipv4_t     ipv4_2;
}

parser ParserImpl(packet_in packet, out headers hdr, inout metadata meta, inout standard_metadata_t standard_metadata) {
    @name(".parse_ipv4") state parse_ipv4 {
        packet.extract<ipv4_t>(hdr.ipv4);
        transition reject;
    }
    @name(".start") state start {
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
                key_match(hdr.ethernet.etherType == t1.key_t1_0_ethernet_etherType);
                if (!hdr.ethernet.isValid())  {
                    bug();
                } 
            }
            if (t1.action_run == flow_def_t1_0__action_type_t.NoAction_0) {
            }
            else  {
                if (t1.action_run == flow_def_t1_0__action_type_t.drop_1) {
                    angelic_assert(true);
                    {
                    }
                }
                else  {
                    if (t1.action_run == flow_def_t1_0__action_type_t.validate_0) {
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
                key_match(hdr.ethernet.etherType == t2.key_t2_0_ethernet_etherType);
                if (!hdr.ethernet.isValid())  {
                    bug();
                } 
            }
            if (t2.action_run == flow_def_t2_0__action_type_t.NoAction_3) {
            }
            else  {
                if (t2.action_run == flow_def_t2_0__action_type_t.drop_3) {
                    angelic_assert(true);
                    {
                    }
                }
                else  {
                    if (t2.action_run == flow_def_t2_0__action_type_t.use_0) {
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
                        ;
                    }
                }
            }
            end_t2_0();
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
