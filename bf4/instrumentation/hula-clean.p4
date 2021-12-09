
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

struct headers {
    ethernet_t    ethernet;
    srcRoute_t[9] srcRoutes;
    ipv4_t        ipv4;
    udp_t         udp;
    hula_t        hula;
}

parser MyParser(packet_in packet, out headers hdr, inout metadata meta, inout standard_metadata_t standard_metadata) {
    state start {
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
        packet.extract<srcRoute_t>(hdr.srcRoutes.next);
        transition select(hdr.srcRoutes.last.bos) {
            1w1: parse_ipv4;
            default: parse_srcRouting;
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
    bit<16> tmp_0;
    qdepth_t old_qdepth_0;
    digest_t old_digest_0;
    bit<16> flow_hash_0;
    bit<16> port_0;
    @name(".NoAction") action NoAction_0() {
    }
    @name("MyIngress.srcindex_qdepth_reg") register<qdepth_t>(32w32) srcindex_qdepth_reg_0;
    @name("MyIngress.srcindex_digest_reg") register<digest_t>(32w32) srcindex_digest_reg_0;
    @name("MyIngress.dstindex_nhop_reg") register<bit<16>>(32w32) dstindex_nhop_reg_0;
    @name("MyIngress.flow_port_reg") register<bit<16>>(32w65536) flow_port_reg_0;
    @name("MyIngress.drop") action drop_1() {
        standard_metadata.egress_spec = 9w511;
    }
    @name("MyIngress.drop") action drop_5() {
        standard_metadata.egress_spec = 9w511;
    }
    @name("MyIngress.drop") action drop_6() {
        standard_metadata.egress_spec = 9w511;
    }
    @name("MyIngress.drop") action drop_7() {
        standard_metadata.egress_spec = 9w511;
    }
    @name("MyIngress.nop") action nop() {
    }
    @name("MyIngress.update_ttl") action update_ttl() {
        hdr.ipv4.ttl = hdr.ipv4.ttl + 8w255;
    }
    @name("MyIngress.set_dmac") action set_dmac(macAddr_t dstAddr) {
        hdr.ethernet.srcAddr = hdr.ethernet.dstAddr;
        hdr.ethernet.dstAddr = dstAddr;
    }
    @name("MyIngress.srcRoute_nhop") action srcRoute_nhop() {
        standard_metadata.egress_spec = (bit<9>)hdr.srcRoutes[0].port;
        hdr.srcRoutes.pop_front(1);
    }
    @name("MyIngress.srcRoute_nhop") action srcRoute_nhop_2() {
        standard_metadata.egress_spec = (bit<9>)hdr.srcRoutes[0].port;
        hdr.srcRoutes.pop_front(1);
    }
    @name("MyIngress.hula_dst") action hula_dst(bit<32> index) {
        meta.index = index;
    }
    @name("MyIngress.hula_set_nhop") action hula_set_nhop(bit<32> index) {
        dstindex_nhop_reg_0.write(index, (bit<16>)standard_metadata.ingress_port);
    }
    @name("MyIngress.hula_get_nhop") action hula_get_nhop(bit<32> index) {
        dstindex_nhop_reg_0.read(tmp_0, index);
        standard_metadata.egress_spec = (bit<9>)tmp_0;
    }
    @name("MyIngress.change_best_path_at_dst") action change_best_path_at_dst() {
        srcindex_qdepth_reg_0.write(meta.index, hdr.hula.qdepth);
        srcindex_digest_reg_0.write(meta.index, hdr.hula.digest);
    }
    @name("MyIngress.return_hula_to_src") action return_hula_to_src() {
        hdr.hula.dir = 1w1;
        standard_metadata.egress_spec = standard_metadata.ingress_port;
    }
    @name("MyIngress.hula_fwd") table hula_fwd_0 {
        key = {
            hdr.ipv4.dstAddr: exact @name("hdr.ipv4.dstAddr") ;
            hdr.ipv4.srcAddr: exact @name("hdr.ipv4.srcAddr") ;
        }
        actions = {
            hula_dst();
            srcRoute_nhop();
        }
        default_action = srcRoute_nhop();
        size = 33;
    }
    @name("MyIngress.hula_bwd") table hula_bwd_0 {
        key = {
            hdr.ipv4.dstAddr: lpm @name("hdr.ipv4.dstAddr") ;
        }
        actions = {
            hula_set_nhop();
            @defaultonly NoAction_0();
        }
        size = 32;
        default_action = NoAction_0();
    }
    @name("MyIngress.hula_src") table hula_src_0 {
        key = {
            hdr.ipv4.srcAddr: exact @name("hdr.ipv4.srcAddr") ;
        }
        actions = {
            drop_1();
            srcRoute_nhop_2();
        }
        default_action = srcRoute_nhop_2();
        size = 2;
    }
    @name("MyIngress.hula_nhop") table hula_nhop_0 {
        key = {
            hdr.ipv4.dstAddr: lpm @name("hdr.ipv4.dstAddr") ;
        }
        actions = {
            hula_get_nhop();
            drop_5();
        }
        default_action = drop_5();
        size = 32;
    }
    @name("MyIngress.dmac") table dmac_0 {
        key = {
            standard_metadata.egress_spec: exact @name("standard_metadata.egress_spec") ;
        }
        actions = {
            set_dmac();
            nop();
        }
        default_action = nop();
        size = 16;
    }
    apply {
        if (hdr.hula.isValid())  {
            if (hdr.hula.dir == 1w0)  {
                switch (hula_fwd_0.apply().action_run) {
                    hula_dst: {
                        srcindex_qdepth_reg_0.read(old_qdepth_0, meta.index);
                        if (old_qdepth_0 > hdr.hula.qdepth) {
                            change_best_path_at_dst();
                            return_hula_to_src();
                        }
                        else {
                            srcindex_digest_reg_0.read(old_digest_0, meta.index);
                            if (old_digest_0 == hdr.hula.digest)  {
                                srcindex_qdepth_reg_0.write(meta.index, hdr.hula.qdepth);
                            } 
                            drop_6();
                        }
                    }
                }

            } 
            else {
                hula_bwd_0.apply();
                hula_src_0.apply();
            }
        } 
        else  {
            if (hdr.ipv4.isValid()) {
                hash<bit<16>, bit<16>, tuple_0, bit<32>>(flow_hash_0, HashAlgorithm.crc16, 16w0, { hdr.ipv4.srcAddr, hdr.ipv4.dstAddr, hdr.udp.srcPort }, 32w65536);
                flow_port_reg_0.read(port_0, (bit<32>)flow_hash_0);
                if (port_0 == 16w0) {
                    hula_nhop_0.apply();
                    flow_port_reg_0.write((bit<32>)flow_hash_0, (bit<16>)standard_metadata.egress_spec);
                }
                else  {
                    standard_metadata.egress_spec = (bit<9>)port_0;
                }
                dmac_0.apply();
            }
            else  {
                drop_7();
            }
        }
        if (hdr.ipv4.isValid())  {
            update_ttl();
        } 
    }
}

control MyEgress(inout headers hdr, inout metadata meta, inout standard_metadata_t standard_metadata) {
    apply {
        if (hdr.hula.isValid() && hdr.hula.dir == 1w0)  {
            if (hdr.hula.qdepth < (qdepth_t)standard_metadata.deq_qdepth)  {
                hdr.hula.qdepth = (qdepth_t)standard_metadata.deq_qdepth;
            } 
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
        update_checksum<tuple_1, bit<16>>(hdr.ipv4.isValid(), { hdr.ipv4.version, hdr.ipv4.ihl, hdr.ipv4.diffserv, hdr.ipv4.totalLen, hdr.ipv4.identification, hdr.ipv4.flags, hdr.ipv4.fragOffset, hdr.ipv4.ttl, hdr.ipv4.protocol, hdr.ipv4.srcAddr, hdr.ipv4.dstAddr }, hdr.ipv4.hdrChecksum, HashAlgorithm.csum16);
    }
}

control MyDeparser(packet_out packet, in headers hdr) {
    apply {
        packet.emit<ethernet_t>(hdr.ethernet);
        packet.emit<hula_t>(hdr.hula);
        packet.emit<srcRoute_t>(hdr.srcRoutes[0]);
        packet.emit<srcRoute_t>(hdr.srcRoutes[1]);
        packet.emit<srcRoute_t>(hdr.srcRoutes[2]);
        packet.emit<srcRoute_t>(hdr.srcRoutes[3]);
        packet.emit<srcRoute_t>(hdr.srcRoutes[4]);
        packet.emit<srcRoute_t>(hdr.srcRoutes[5]);
        packet.emit<srcRoute_t>(hdr.srcRoutes[6]);
        packet.emit<srcRoute_t>(hdr.srcRoutes[7]);
        packet.emit<srcRoute_t>(hdr.srcRoutes[8]);
        packet.emit<ipv4_t>(hdr.ipv4);
        packet.emit<udp_t>(hdr.udp);
    }
}

V1Switch<headers, metadata>(MyParser(), MyVerifyChecksum(), MyIngress(), MyEgress(), MyComputeChecksum(), MyDeparser()) main;

void copy_field_list(in metadata from, inout metadata to, in standard_metadata_t smfrom, inout standard_metadata_t smto, in bit<16> discriminator) {
    ;
}
