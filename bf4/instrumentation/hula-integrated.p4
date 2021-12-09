extern H havoc<H>();
extern void assert(in bool condition);
extern void assume(in bool condition);
extern void oob();
extern void dontCare();
extern void do_drop();
extern mutable_packet {
    mutable_packet(int size);
    void extract<T>(out T hdr);
    void extract<T>(out T variableSizeHeader, in bit<32> variableFieldSizeInBits);
    T lookahead<T>();
    void advance(in bit<32> sizeInBits);
    bit<32> length();
    void emit<T>(in T hdr);
}

extern void copyPacket(mutable_packet self, @readonly mutable_packet other);
extern void prependPacket(mutable_packet self, @readonly mutable_packet other);
extern void readPacket(mutable_packet self);
extern void emptyPacket(mutable_packet self);
extern void do_send<H>(in H port, mutable_packet pin);
enum flow_def_hula_bwd_0__action_type_t {
    hula_set_nhop,
    NoAction_0
}

struct flow_def_hula_bwd_0 {
    bool                               hit;
    bool                               reach;
    flow_def_hula_bwd_0__action_type_t action_run;
    bit<32>                            hula_set_nhop__index;
    @matchKind("lpm") 
    bit<32>                            key_hula_bwd_0_hdr_ipv4_dstAddr__val;
    @matchKind("lpm") 
    bit<32>                            key_hula_bwd_0_hdr_ipv4_dstAddr__prefix;
}

@controlled extern flow_def_hula_bwd_0 query_hula_bwd_0(@matchKind("lpm") in bit<32> hula_bwd_0_hdr_ipv4_dstAddr);
extern void end_hula_bwd_0();
enum flow_def_hula_fwd_0__action_type_t {
    hula_dst,
    srcRoute_nhop
}

struct flow_def_hula_fwd_0 {
    bool                               hit;
    bool                               reach;
    flow_def_hula_fwd_0__action_type_t action_run;
    bit<32>                            hula_dst__index;
    @matchKind("exact") 
    bit<32>                            key_hula_fwd_0_hdr_ipv4_dstAddr;
    @matchKind("exact") 
    bit<32>                            key_hula_fwd_0_hdr_ipv4_srcAddr;
}

@controlled extern flow_def_hula_fwd_0 query_hula_fwd_0(@matchKind("exact") in bit<32> hula_fwd_0_hdr_ipv4_dstAddr, @matchKind("exact") in bit<32> hula_fwd_0_hdr_ipv4_srcAddr);
extern void end_hula_fwd_0();
enum flow_def_dmac_0__action_type_t {
    set_dmac,
    nop
}

struct flow_def_dmac_0 {
    bool                           hit;
    bool                           reach;
    flow_def_dmac_0__action_type_t action_run;
    bit<48>                        set_dmac__dstAddr;
    @matchKind("exact") 
    bit<9>                         key_dmac_0_standard_metadata_egress_spec;
}

@controlled extern flow_def_dmac_0 query_dmac_0(@matchKind("exact") in bit<9> dmac_0_standard_metadata_egress_spec);
extern void end_dmac_0();
enum flow_def_hula_nhop_0__action_type_t {
    hula_get_nhop,
    drop_5
}

struct flow_def_hula_nhop_0 {
    bool                                hit;
    bool                                reach;
    flow_def_hula_nhop_0__action_type_t action_run;
    bit<32>                             hula_get_nhop__index;
    @matchKind("lpm") 
    bit<32>                             key_hula_nhop_0_hdr_ipv4_dstAddr__val;
    @matchKind("lpm") 
    bit<32>                             key_hula_nhop_0_hdr_ipv4_dstAddr__prefix;
}

@controlled extern flow_def_hula_nhop_0 query_hula_nhop_0(@matchKind("lpm") in bit<32> hula_nhop_0_hdr_ipv4_dstAddr);
extern void end_hula_nhop_0();
enum flow_def_hula_src_0__action_type_t {
    drop_1,
    srcRoute_nhop_2
}

struct flow_def_hula_src_0 {
    bool                               hit;
    bool                               reach;
    flow_def_hula_src_0__action_type_t action_run;
    @matchKind("exact") 
    bit<32>                            key_hula_src_0_hdr_ipv4_srcAddr;
}

@controlled extern flow_def_hula_src_0 query_hula_src_0(@matchKind("exact") in bit<32> hula_src_0_hdr_ipv4_srcAddr);
extern void end_hula_src_0();
extern void key_match(in bool condition);
extern void angelic_assert(in bool condition);
extern void bug();

#include <core.p4>

#include <v1model.p4>

typedef bit<48> macAddr_t;
typedef bit<32> ip4Addr_t;
typedef bit<15> qdepth_t;
typedef bit<32> digest_t;
header ethernet_t {
    macAddr_t dstAddr;
    macAddr_t srcAddr;
    bit<16>   etherType;
}

header srcRoute_t {
    bit<1>  bos;
    bit<15> port;
}

header hula_t {
    bit<1>   dir;
    qdepth_t qdepth;
    digest_t digest;
}

header ipv4_t {
    bit<4>    version;
    bit<4>    ihl;
    bit<8>    diffserv;
    bit<16>   totalLen;
    bit<16>   identification;
    bit<3>    flags;
    bit<13>   fragOffset;
    bit<8>    ttl;
    bit<8>    protocol;
    bit<16>   hdrChecksum;
    ip4Addr_t srcAddr;
    ip4Addr_t dstAddr;
}

header udp_t {
    bit<16> srcPort;
    bit<16> dstPort;
    bit<16> length_;
    bit<16> checksum;
}

struct metadata {
    bit<32> index;
}

@array struct srcRoute_t_9 {
    bit<16>       nxt;
    @raw 
    srcRoute_t[9] elements;
}

struct headers {
    ethernet_t   ethernet;
    srcRoute_t_9 srcRoutes;
    ipv4_t       ipv4;
    udp_t        udp;
    hula_t       hula;
}

parser MyParser(mutable_packet packet, out headers hdr, inout metadata meta, inout standard_metadata_t standard_metadata, inout error err) {
    state start {
        hdr.srcRoutes.nxt = 16w0;
        packet.extract<ethernet_t>(hdr.ethernet);
        transition select(hdr.ethernet.etherType) {
            16w0x2345: parse_hula;
            16w0x800: parse_ipv4;
            default: accept;
        }
    }
    state parse_hula {
        packet.extract<hula_t>(hdr.hula);
        transition parse_srcRouting;
    }
    state parse_srcRouting {
        transition select(hdr.srcRoutes.nxt < 16w9) {
            true: parse_srcRouting_0;
            default: reject;
        }
    }
    state parse_ipv4 {
        packet.extract<ipv4_t>(hdr.ipv4);
        transition select(hdr.ipv4.protocol) {
            8w17: parse_udp;
            default: accept;
        }
    }
    state parse_udp {
        packet.extract<udp_t>(hdr.udp);
        transition accept;
    }
    state parse_srcRouting_0 {
        packet.extract<srcRoute_t>(hdr.srcRoutes.elements[hdr.srcRoutes.nxt]);
        hdr.srcRoutes.nxt = hdr.srcRoutes.nxt + 16w1;
        transition select(hdr.srcRoutes.elements[hdr.srcRoutes.nxt + 16w65535].bos) {
            1w1: parse_ipv4;
            default: parse_srcRouting;
        }
    }
}

control MyVerifyChecksum(inout headers hdr, inout metadata meta) {
    apply {
    }
}

struct tuple_0 {
    bit<32> field;
    bit<32> field_0;
    bit<16> field_1;
}

control MyIngress(inout headers hdr, inout metadata meta, inout standard_metadata_t standard_metadata) {
    bool __track_egress_spec_0;
    bit<16> tmp_5;
    qdepth_t old_qdepth_0;
    digest_t old_digest_0;
    bit<16> flow_hash_0;
    bit<16> port_0;
    flow_def_hula_fwd_0 hula_fwd;
    flow_def_hula_bwd_0 hula_bwd;
    flow_def_hula_src_0 hula_src;
    flow_def_hula_nhop_0 hula_nhop;
    flow_def_dmac_0 dmac;
    flow_def_hula_fwd_0 tmp_6;
    flow_def_hula_bwd_0 tmp_7;
    flow_def_hula_src_0 tmp_8;
    flow_def_hula_nhop_0 tmp_9;
    flow_def_dmac_0 tmp_10;
    @name("MyIngress.srcindex_qdepth_reg") register<qdepth_t>(32w32) srcindex_qdepth_reg_0;
    @name("MyIngress.srcindex_digest_reg") register<digest_t>(32w32) srcindex_digest_reg_0;
    @name("MyIngress.dstindex_nhop_reg") register<bit<16>>(32w32) dstindex_nhop_reg_0;
    @name("MyIngress.flow_port_reg") register<bit<16>>(32w65536) flow_port_reg_0;
    apply {
        __track_egress_spec_0 = false;
        if (hdr.hula.isValid()) {
            if (hdr.hula.isValid()) {
                if (hdr.hula.dir == 1w0) {
                    tmp_6 = query_hula_fwd_0(hdr.ipv4.dstAddr, hdr.ipv4.srcAddr);
                    hula_fwd = tmp_6;
                    if (hula_fwd.hit) {
                        key_match(hdr.ipv4.dstAddr == hula_fwd.key_hula_fwd_0_hdr_ipv4_dstAddr && hdr.ipv4.srcAddr == hula_fwd.key_hula_fwd_0_hdr_ipv4_srcAddr);
                        if (!hdr.ipv4.isValid()) {
                            bug();
                        }
                        if (!hdr.ipv4.isValid()) {
                            bug();
                        }
                    }
                    if (hula_fwd.action_run == flow_def_hula_fwd_0__action_type_t.srcRoute_nhop) {
                        angelic_assert(true);
                        if (hdr.srcRoutes.elements[0].isValid()) {
                            standard_metadata.egress_spec = (bit<9>)hdr.srcRoutes.elements[0].port;
                            __track_egress_spec_0 = true;
                        }
                        else {
                            bug();
                        }
                        hdr.srcRoutes.elements[0] = hdr.srcRoutes.elements[1];
                        hdr.srcRoutes.elements[1] = hdr.srcRoutes.elements[2];
                        hdr.srcRoutes.elements[2] = hdr.srcRoutes.elements[3];
                        hdr.srcRoutes.elements[3] = hdr.srcRoutes.elements[4];
                        hdr.srcRoutes.elements[4] = hdr.srcRoutes.elements[5];
                        hdr.srcRoutes.elements[5] = hdr.srcRoutes.elements[6];
                        hdr.srcRoutes.elements[6] = hdr.srcRoutes.elements[7];
                        hdr.srcRoutes.elements[7] = hdr.srcRoutes.elements[8];
                        hdr.srcRoutes.elements[8].setInvalid();
                        if (hdr.srcRoutes.nxt < 16w1) {
                            hdr.srcRoutes.nxt = 16w0;
                        }
                        else {
                            hdr.srcRoutes.nxt = hdr.srcRoutes.nxt + 16w65535;
                        }
                    }
                    else {
                        if (hula_fwd.action_run == flow_def_hula_fwd_0__action_type_t.hula_dst) {
                            angelic_assert(true);
                            meta.index = hula_fwd.hula_dst__index;
                        }
                        else {
                            ;
                        }
                    }
                    end_hula_fwd_0();
                    if (hula_fwd.action_run == flow_def_hula_fwd_0__action_type_t.hula_dst) {
                        if (meta.index >= 32w32) {
                            bug();
                        }
                        srcindex_qdepth_reg_0.read(old_qdepth_0, meta.index);
                        if (hdr.hula.isValid()) {
                            if (old_qdepth_0 > hdr.hula.qdepth) {
                                if (hdr.hula.isValid()) {
                                    if (meta.index >= 32w32) {
                                        bug();
                                    }
                                    srcindex_qdepth_reg_0.write(meta.index, hdr.hula.qdepth);
                                }
                                else {
                                    bug();
                                }
                                if (hdr.hula.isValid()) {
                                    if (meta.index >= 32w32) {
                                        bug();
                                    }
                                    srcindex_digest_reg_0.write(meta.index, hdr.hula.digest);
                                }
                                else {
                                    bug();
                                }
                                if (hdr.hula.isValid()) {
                                    hdr.hula.dir = 1w1;
                                }
                                else {
                                    bug();
                                }
                                standard_metadata.egress_spec = standard_metadata.ingress_port;
                                __track_egress_spec_0 = true;
                            }
                            else {
                                if (meta.index >= 32w32) {
                                    bug();
                                }
                                srcindex_digest_reg_0.read(old_digest_0, meta.index);
                                if (hdr.hula.isValid()) {
                                    if (old_digest_0 == hdr.hula.digest) {
                                        if (hdr.hula.isValid()) {
                                            if (meta.index >= 32w32) {
                                                bug();
                                            }
                                            srcindex_qdepth_reg_0.write(meta.index, hdr.hula.qdepth);
                                        }
                                        else {
                                            bug();
                                        }
                                    }
                                }
                                else {
                                    bug();
                                }
                                standard_metadata.egress_spec = 9w511;
                                __track_egress_spec_0 = true;
                            }
                        }
                        else {
                            bug();
                        }
                    }
                    else {
                        ;
                    }
                }
                else {
                    tmp_7 = query_hula_bwd_0(hdr.ipv4.dstAddr);
                    hula_bwd = tmp_7;
                    if (hula_bwd.hit) {
                        key_match(hdr.ipv4.dstAddr & (32w1 << hula_bwd.key_hula_bwd_0_hdr_ipv4_dstAddr__prefix) + 32w4294967295 == hula_bwd.key_hula_bwd_0_hdr_ipv4_dstAddr__val & (32w1 << hula_bwd.key_hula_bwd_0_hdr_ipv4_dstAddr__prefix) + 32w4294967295);
                        if (!(hdr.ipv4.isValid() || (32w1 << hula_bwd.key_hula_bwd_0_hdr_ipv4_dstAddr__prefix) + 32w4294967295 == 32w0)) {
                            bug();
                        }
                    }
                    if (hula_bwd.action_run == flow_def_hula_bwd_0__action_type_t.NoAction_0) {
                        ;
                    }
                    else {
                        if (hula_bwd.action_run == flow_def_hula_bwd_0__action_type_t.hula_set_nhop) {
                            angelic_assert(true);
                            if (hula_bwd.hula_set_nhop__index >= 32w32) {
                                bug();
                            }
                            dstindex_nhop_reg_0.write(hula_bwd.hula_set_nhop__index, (bit<16>)standard_metadata.ingress_port);
                        }
                        else {
                            ;
                        }
                    }
                    end_hula_bwd_0();
                    tmp_8 = query_hula_src_0(hdr.ipv4.srcAddr);
                    hula_src = tmp_8;
                    if (hula_src.hit) {
                        key_match(hdr.ipv4.srcAddr == hula_src.key_hula_src_0_hdr_ipv4_srcAddr);
                        if (!hdr.ipv4.isValid()) {
                            bug();
                        }
                    }
                    if (hula_src.action_run == flow_def_hula_src_0__action_type_t.srcRoute_nhop_2) {
                        angelic_assert(true);
                        if (hdr.srcRoutes.elements[0].isValid()) {
                            standard_metadata.egress_spec = (bit<9>)hdr.srcRoutes.elements[0].port;
                            __track_egress_spec_0 = true;
                        }
                        else {
                            bug();
                        }
                        hdr.srcRoutes.elements[0] = hdr.srcRoutes.elements[1];
                        hdr.srcRoutes.elements[1] = hdr.srcRoutes.elements[2];
                        hdr.srcRoutes.elements[2] = hdr.srcRoutes.elements[3];
                        hdr.srcRoutes.elements[3] = hdr.srcRoutes.elements[4];
                        hdr.srcRoutes.elements[4] = hdr.srcRoutes.elements[5];
                        hdr.srcRoutes.elements[5] = hdr.srcRoutes.elements[6];
                        hdr.srcRoutes.elements[6] = hdr.srcRoutes.elements[7];
                        hdr.srcRoutes.elements[7] = hdr.srcRoutes.elements[8];
                        hdr.srcRoutes.elements[8].setInvalid();
                        if (hdr.srcRoutes.nxt < 16w1) {
                            hdr.srcRoutes.nxt = 16w0;
                        }
                        else {
                            hdr.srcRoutes.nxt = hdr.srcRoutes.nxt + 16w65535;
                        }
                    }
                    else {
                        if (hula_src.action_run == flow_def_hula_src_0__action_type_t.drop_1) {
                            angelic_assert(true);
                            standard_metadata.egress_spec = 9w511;
                            __track_egress_spec_0 = true;
                        }
                        else {
                            ;
                        }
                    }
                    end_hula_src_0();
                }
            }
            else {
                bug();
            }
        }
        else {
            if (hdr.ipv4.isValid()) {
                hash<bit<16>, bit<16>, tuple_0, bit<32>>(flow_hash_0, HashAlgorithm.crc16, 16w0, tuple_0 {field = hdr.ipv4.srcAddr,field_0 = hdr.ipv4.dstAddr,field_1 = hdr.udp.srcPort}, 32w65536);
                if ((bit<32>)flow_hash_0 >= 32w65536) {
                    bug();
                }
                flow_port_reg_0.read(port_0, (bit<32>)flow_hash_0);
                if (port_0 == 16w0) {
                    tmp_9 = query_hula_nhop_0(hdr.ipv4.dstAddr);
                    hula_nhop = tmp_9;
                    if (hula_nhop.hit) {
                        key_match(hdr.ipv4.dstAddr & (32w1 << hula_nhop.key_hula_nhop_0_hdr_ipv4_dstAddr__prefix) + 32w4294967295 == hula_nhop.key_hula_nhop_0_hdr_ipv4_dstAddr__val & (32w1 << hula_nhop.key_hula_nhop_0_hdr_ipv4_dstAddr__prefix) + 32w4294967295);
                        if (!(hdr.ipv4.isValid() || (32w1 << hula_nhop.key_hula_nhop_0_hdr_ipv4_dstAddr__prefix) + 32w4294967295 == 32w0)) {
                            bug();
                        }
                    }
                    if (hula_nhop.action_run == flow_def_hula_nhop_0__action_type_t.drop_5) {
                        angelic_assert(true);
                        standard_metadata.egress_spec = 9w511;
                        __track_egress_spec_0 = true;
                    }
                    else {
                        if (hula_nhop.action_run == flow_def_hula_nhop_0__action_type_t.hula_get_nhop) {
                            angelic_assert(true);
                            if (hula_nhop.hula_get_nhop__index >= 32w32) {
                                bug();
                            }
                            dstindex_nhop_reg_0.read(tmp_5, hula_nhop.hula_get_nhop__index);
                            standard_metadata.egress_spec = (bit<9>)tmp_5;
                            __track_egress_spec_0 = true;
                        }
                        else {
                            ;
                        }
                    }
                    end_hula_nhop_0();
                    if ((bit<32>)flow_hash_0 >= 32w65536) {
                        bug();
                    }
                    flow_port_reg_0.write((bit<32>)flow_hash_0, (bit<16>)standard_metadata.egress_spec);
                }
                else {
                    standard_metadata.egress_spec = (bit<9>)port_0;
                    __track_egress_spec_0 = true;
                }
                tmp_10 = query_dmac_0(standard_metadata.egress_spec);
                dmac = tmp_10;
                if (dmac.hit) {
                    key_match(standard_metadata.egress_spec == dmac.key_dmac_0_standard_metadata_egress_spec);
                }
                if (dmac.action_run == flow_def_dmac_0__action_type_t.nop) {
                    angelic_assert(true);
                }
                else {
                    if (dmac.action_run == flow_def_dmac_0__action_type_t.set_dmac) {
                        angelic_assert(true);
                        if (hdr.ethernet.isValid() && hdr.ethernet.isValid()) {
                            hdr.ethernet.srcAddr = hdr.ethernet.dstAddr;
                        }
                        else {
                            bug();
                        }
                        if (hdr.ethernet.isValid()) {
                            hdr.ethernet.dstAddr = dmac.set_dmac__dstAddr;
                        }
                        else {
                            bug();
                        }
                    }
                    else {
                        ;
                    }
                }
                end_dmac_0();
            }
            else {
                standard_metadata.egress_spec = 9w511;
                __track_egress_spec_0 = true;
            }
        }
        if (hdr.ipv4.isValid()) {
            if (hdr.ipv4.isValid() && hdr.ipv4.isValid()) {
                hdr.ipv4.ttl = hdr.ipv4.ttl + 8w255;
            }
            else {
                bug();
            }
        }
        if (!__track_egress_spec_0) {
            bug();
        }
    }
}

control MyEgress(inout headers hdr, inout metadata meta, inout standard_metadata_t standard_metadata) {
    apply {
        if (hdr.hula.isValid() || !hdr.hula.isValid()) {
            if (hdr.hula.isValid() && hdr.hula.dir == 1w0) {
                if (hdr.hula.isValid()) {
                    if (hdr.hula.qdepth < (qdepth_t)standard_metadata.deq_qdepth) {
                        if (hdr.hula.isValid()) {
                            hdr.hula.qdepth = (qdepth_t)standard_metadata.deq_qdepth;
                        }
                        else {
                            bug();
                        }
                    }
                }
                else {
                    bug();
                }
            }
        }
        else {
            bug();
        }
    }
}

struct tuple_1 {
    bit<4>  field_2;
    bit<4>  field_3;
    bit<8>  field_4;
    bit<16> field_5;
    bit<16> field_6;
    bit<3>  field_7;
    bit<13> field_8;
    bit<8>  field_9;
    bit<8>  field_10;
    bit<32> field_11;
    bit<32> field_12;
}

control MyComputeChecksum(inout headers hdr, inout metadata meta) {
    apply {
    }
}

control MyDeparser(mutable_packet packet, in headers hdr) {
    apply {
        packet.emit<ethernet_t>(hdr.ethernet);
        packet.emit<hula_t>(hdr.hula);
        packet.emit<srcRoute_t>(hdr.srcRoutes.elements[0]);
        packet.emit<srcRoute_t>(hdr.srcRoutes.elements[1]);
        packet.emit<srcRoute_t>(hdr.srcRoutes.elements[2]);
        packet.emit<srcRoute_t>(hdr.srcRoutes.elements[3]);
        packet.emit<srcRoute_t>(hdr.srcRoutes.elements[4]);
        packet.emit<srcRoute_t>(hdr.srcRoutes.elements[5]);
        packet.emit<srcRoute_t>(hdr.srcRoutes.elements[6]);
        packet.emit<srcRoute_t>(hdr.srcRoutes.elements[7]);
        packet.emit<srcRoute_t>(hdr.srcRoutes.elements[8]);
        packet.emit<ipv4_t>(hdr.ipv4);
        packet.emit<udp_t>(hdr.udp);
    }
}

V1Switch<headers, metadata>(MyParser(), MyVerifyChecksum(), MyIngress(), MyEgress(), MyComputeChecksum(), MyDeparser()) main;

void copy_field_list(in metadata from, inout metadata to, in standard_metadata_t smfrom, inout standard_metadata_t smto, in bit<16> discriminator) {
}
typedef bit<9> PortId_t;
typedef bit<48> Timestamp_t;
typedef bit<16> CloneSessionId_t;
typedef bit<16> MulticastGroup_t;
typedef bit<16> EgressInstance_t;
typedef bit<3> ClassOfService_t;
typedef bit<32> PacketLength_t;
typedef bit<32> InstanceType_t;
const InstanceType_t PKT_INSTANCE_TYPE_NORMAL_0 = 32w0;
const InstanceType_t PKT_INSTANCE_TYPE_INGRESS_CLONE_0 = 32w1;
const InstanceType_t PKT_INSTANCE_TYPE_EGRESS_CLONE_0 = 32w2;
const InstanceType_t PKT_INSTANCE_TYPE_RESUBMIT_0 = 32w3;
const InstanceType_t PKT_INSTANCE_TYPE_REPLICATION_0 = 32w4;
const InstanceType_t PKT_INSTANCE_TYPE_RECIRC_0 = 32w5;
extern bool platform_port_valid(in PortId_t p);
extern Timestamp_t now();
extern bool is_cpu_port(in PortId_t p);
@controlled extern bool constrain(@readonly mutable_packet pin);
@impl("parse_and_run_") @noreturn extern void parse_and_run(mutable_packet pin, inout metadata metas_, inout standard_metadata_t standard_meta);
@impl("PSAImpl_egress_start_") @noreturn extern void PSAImpl_egress_start(mutable_packet p, inout headers hdrs_, inout metadata metas_, inout standard_metadata_t standard_meta);
@impl("PSAImpl_ingress_start_") @noreturn extern void PSAImpl_ingress_start(mutable_packet p, inout headers hdrs_, inout metadata metas_, inout standard_metadata_t standard_meta);
extern void zero_out<T>(inout T x);
struct clone_session_t {
    bool             exists;
    PortId_t         port;
    EgressInstance_t instance;
}

struct clone_session_properties_t {
    bool             exists;
    ClassOfService_t class_of_service;
    bool             trunc;
    PacketLength_t   plen;
}

@controlled extern clone_session_t qquery_first_clone_pre(in CloneSessionId_t cs);
@controlled extern clone_session_t qquery_all_clone_pre(in CloneSessionId_t cs);
@controlled extern clone_session_t qquery_first_mcast(in MulticastGroup_t cs);
@controlled extern clone_session_properties_t qquery_clone_session_properties(in CloneSessionId_t cs);
void PSAImpl_egress_start_(mutable_packet p, inout headers hdrs_, inout metadata metas_, inout standard_metadata_t standard_meta) {
    headers clone_hdrs_0;
    metadata clone_metas_0;
    standard_metadata_t clone_sm_0;
    CloneSessionId_t clone_session_0;
    CloneSessionId_t clone_field_list_0;
    clone_session_t cs_0;
    bit<32> recirculate_flag_0;
    MyEgress() eg;
    ;
    MyDeparser() dep;
    ;
    clone_sm_0 = standard_meta;
    clone_hdrs_0 = hdrs_;
    clone_metas_0 = metas_;
    eg.apply(hdrs_, metas_, standard_meta);
    clone_session_0 = standard_meta.clone_spec[15:0];
    clone_field_list_0 = standard_meta.clone_spec[31:16];
    if (clone_session_0 != 16w0) {
        cs_0 = qquery_first_clone_pre(clone_session_0);
        copy_field_list(metas_, clone_metas_0, standard_meta, clone_sm_0, (bit<16>)clone_field_list_0);
        clone_sm_0.instance_type = PKT_INSTANCE_TYPE_EGRESS_CLONE_0;
        clone_sm_0.egress_port = cs_0.port;
        clone_sm_0.resubmit_flag = (bit<32>)32w0;
        clone_sm_0.clone_spec = (bit<32>)32w0;
        if (havoc<bool>()) {
            PSAImpl_egress_start(p, clone_hdrs_0, clone_metas_0, clone_sm_0);
        }
    }
    if (standard_meta.egress_spec == 9w511) {
        do_drop();
    }
    dep.apply(p, hdrs_);
    recirculate_flag_0 = standard_meta.recirculate_flag;
    if (recirculate_flag_0 != 32w0) {
        {
            clone_metas_0.index = 32w0;
        }
        copy_field_list(metas_, clone_metas_0, standard_meta, clone_sm_0, (bit<16>)recirculate_flag_0);
        clone_sm_0.resubmit_flag = (bit<32>)32w0;
        clone_sm_0.clone_spec = (bit<32>)32w0;
        clone_sm_0.recirculate_flag = (bit<32>)32w0;
        clone_sm_0.egress_spec = (bit<9>)9w0;
        clone_sm_0.egress_port = (bit<9>)9w0;
        clone_sm_0.instance_type = PKT_INSTANCE_TYPE_RECIRC_0;
        copy_field_list(metas_, clone_metas_0, standard_meta, clone_sm_0, (bit<16>)recirculate_flag_0);
        parse_and_run(p, clone_metas_0, clone_sm_0);
    }
    do_send(standard_meta.egress_port, p);
}
void PSAImpl_ingress_start_(mutable_packet p, inout headers hdrs_, inout metadata metas_, inout standard_metadata_t standard_meta) {
    headers clone_hdrs_1;
    metadata clone_metas_1;
    standard_metadata_t clone_sm_1;
    CloneSessionId_t clone_session_1;
    CloneSessionId_t clone_field_list_1;
    MulticastGroup_t mgid_0;
    bit<32> resubmit_flag_0;
    clone_session_t cs_1;
    clone_session_t ms_0;
    MyIngress() ig;
    ;
    clone_sm_1 = standard_meta;
    clone_hdrs_1 = hdrs_;
    clone_metas_1 = metas_;
    ig.apply(hdrs_, metas_, standard_meta);
    clone_session_1 = standard_meta.clone_spec[15:0];
    clone_field_list_1 = standard_meta.clone_spec[31:16];
    mgid_0 = standard_meta.mcast_grp;
    resubmit_flag_0 = standard_meta.resubmit_flag;
    if (clone_session_1 != 16w0) {
        cs_1 = qquery_first_clone_pre(clone_session_1);
        copy_field_list(metas_, clone_metas_1, standard_meta, clone_sm_1, (bit<16>)clone_field_list_1);
        clone_sm_1.egress_port = cs_1.port;
        clone_sm_1.resubmit_flag = (bit<32>)32w0;
        clone_sm_1.clone_spec = (bit<32>)32w0;
        clone_sm_1.recirculate_flag = (bit<32>)32w0;
        clone_sm_1.egress_spec = (bit<9>)9w0;
        clone_sm_1.egress_port = (bit<9>)9w0;
        clone_sm_1.instance_type = PKT_INSTANCE_TYPE_INGRESS_CLONE_0;
        if (havoc<bool>()) {
            PSAImpl_egress_start(p, clone_hdrs_1, clone_metas_1, clone_sm_1);
        }
        standard_meta.resubmit_flag = (bit<32>)32w0;
        standard_meta.clone_spec = (bit<32>)32w0;
        standard_meta.recirculate_flag = (bit<32>)32w0;
    }
    if (resubmit_flag_0 != 32w0) {
        copy_field_list(metas_, clone_metas_1, standard_meta, clone_sm_1, (bit<16>)resubmit_flag_0);
        clone_sm_1 = standard_meta;
        clone_sm_1.resubmit_flag = (bit<32>)32w0;
        clone_sm_1.clone_spec = (bit<32>)32w0;
        clone_sm_1.recirculate_flag = (bit<32>)32w0;
        clone_sm_1.egress_spec = (bit<9>)9w0;
        clone_sm_1.egress_port = (bit<9>)9w0;
        clone_sm_1.instance_type = PKT_INSTANCE_TYPE_RESUBMIT_0;
        PSAImpl_ingress_start(p, clone_hdrs_1, clone_metas_1, clone_sm_1);
    }
    if (mgid_0 != 16w0) {
        standard_meta.instance_type = PKT_INSTANCE_TYPE_REPLICATION_0;
        ms_0 = qquery_first_mcast(mgid_0);
        standard_meta.egress_port = ms_0.port;
        standard_meta.egress_rid = ms_0.instance;
        PSAImpl_egress_start(p, hdrs_, metas_, standard_meta);
    }
    if (standard_meta.egress_spec == 9w511) {
        do_drop();
    }
    standard_meta.egress_port = standard_meta.egress_spec;
    standard_meta.instance_type = PKT_INSTANCE_TYPE_NORMAL_0;
    PSAImpl_egress_start(p, hdrs_, metas_, standard_meta);
}
void parse_and_run_(mutable_packet pin, inout metadata metas_, inout standard_metadata_t standard_meta) {
    error last_0;
    headers hdrs;
    standard_meta.ingress_global_timestamp = now();
    {
        hdrs.ethernet.setInvalid();
        hdrs.srcRoutes.nxt = 16w0;
        hdrs.srcRoutes.elements[0].setInvalid();
        hdrs.srcRoutes.elements[1].setInvalid();
        hdrs.srcRoutes.elements[2].setInvalid();
        hdrs.srcRoutes.elements[3].setInvalid();
        hdrs.srcRoutes.elements[4].setInvalid();
        hdrs.srcRoutes.elements[5].setInvalid();
        hdrs.srcRoutes.elements[6].setInvalid();
        hdrs.srcRoutes.elements[7].setInvalid();
        hdrs.srcRoutes.elements[8].setInvalid();
        hdrs.ipv4.setInvalid();
        hdrs.udp.setInvalid();
        hdrs.hula.setInvalid();
    }
    MyParser() p;
    ;
    last_0 = error.NoError;
    p.apply(pin, hdrs, metas_, standard_meta, last_0);
    standard_meta.parser_error = last_0;
    PSAImpl_ingress_start(pin, hdrs, metas_, standard_meta);
}
void run() {
    PortId_t p_0;
    standard_metadata_t standard_meta_0;
    error last_1;
    metadata metas;
    mutable_packet(4096) pin;
    readPacket(pin);
    p_0 = havoc<PortId_t>();
    if (!platform_port_valid(p_0)) {
        do_drop();
    }
    if (is_cpu_port(p_0)) {
        if (!constrain(pin)) {
            do_drop();
        }
    }
    else {
        angelic_assert(true);
    }
    {
        standard_meta_0.ingress_port = 9w0;
        standard_meta_0.egress_spec = 9w0;
        standard_meta_0.egress_port = 9w0;
        standard_meta_0.clone_spec = 32w0;
        standard_meta_0.instance_type = 32w0;
        standard_meta_0.drop = 1w0;
        standard_meta_0.recirculate_port = 16w0;
        standard_meta_0.packet_length = 32w0;
        standard_meta_0.enq_timestamp = 32w0;
        standard_meta_0.enq_qdepth = 19w0;
        standard_meta_0.deq_timedelta = 32w0;
        standard_meta_0.deq_qdepth = 19w0;
        standard_meta_0.ingress_global_timestamp = 48w0;
        standard_meta_0.egress_global_timestamp = 48w0;
        standard_meta_0.lf_field_list = 32w0;
        standard_meta_0.mcast_grp = 16w0;
        standard_meta_0.resubmit_flag = 32w0;
        standard_meta_0.egress_rid = 16w0;
        standard_meta_0.recirculate_flag = 32w0;
        standard_meta_0.checksum_error = 1w0;
        standard_meta_0.priority = 3w0;
        standard_meta_0.deflection_flag = 1w0;
        standard_meta_0.deflect_on_drop = 1w0;
        standard_meta_0.enq_congest_stat = 2w0;
        standard_meta_0.deq_congest_stat = 2w0;
        standard_meta_0.mcast_hash = 13w0;
        standard_meta_0.ingress_cos = 3w0;
        standard_meta_0.packet_color = 2w0;
        standard_meta_0.qid = 5w0;
    }
    standard_meta_0.ingress_port = p_0;
    standard_meta_0.ingress_global_timestamp = now();
    {
        metas.index = 32w0;
    }
    standard_meta_0.instance_type = PKT_INSTANCE_TYPE_NORMAL_0;
    parse_and_run(pin, metas, standard_meta_0);
}
