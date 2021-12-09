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
    bool __track_egress_spec;
    bit<16> tmp;
    qdepth_t old_qdepth;
    digest_t old_digest;
    bit<16> flow_hash;
    bit<16> port_1;
    @name(".NoAction") action NoAction_0() {
    }
    @name("MyIngress.srcindex_qdepth_reg") register<qdepth_t>(32w32) srcindex_qdepth_reg;
    @name("MyIngress.srcindex_digest_reg") register<digest_t>(32w32) srcindex_digest_reg;
    @name("MyIngress.dstindex_nhop_reg") register<bit<16>>(32w32) dstindex_nhop_reg;
    @name("MyIngress.flow_port_reg") register<bit<16>>(32w65536) flow_port_reg;
    @name("MyIngress.drop") action drop_1() {
        {
            standard_metadata.egress_spec = 9w511;
            __track_egress_spec = true;
        }
    }
    @name("MyIngress.drop") action drop_5() {
        {
            standard_metadata.egress_spec = 9w511;
            __track_egress_spec = true;
        }
    }
    @name("MyIngress.drop") action drop_6() {
        {
            standard_metadata.egress_spec = 9w511;
            __track_egress_spec = true;
        }
    }
    @name("MyIngress.drop") action drop_7() {
        {
            standard_metadata.egress_spec = 9w511;
            __track_egress_spec = true;
        }
    }
    @name("MyIngress.nop") action nop() {
    }
    @name("MyIngress.update_ttl") action update_ttl() {
        {
            if (hdr.ipv4.isValid() && hdr.ipv4.isValid())  {
                hdr.ipv4.ttl = hdr.ipv4.ttl + 8w255;
            } 
            else  {
                bug();
            }
        }
    }
    @name("MyIngress.set_dmac") action set_dmac(macAddr_t dstAddr) {
        {
            if (hdr.ethernet.isValid() && hdr.ethernet.isValid())  {
                hdr.ethernet.srcAddr = hdr.ethernet.dstAddr;
            } 
            else  {
                bug();
            }
        }
        {
            if (hdr.ethernet.isValid())  {
                hdr.ethernet.dstAddr = dstAddr;
            } 
            else  {
                bug();
            }
        }
    }
    @name("MyIngress.srcRoute_nhop") action srcRoute_nhop() {
        {
            if (hdr.srcRoutes[0].isValid()) {
                standard_metadata.egress_spec = (bit<9>)hdr.srcRoutes[0].port;
                __track_egress_spec = true;
            }
            else  {
                bug();
            }
        }
        hdr.srcRoutes.pop_front(1);
    }
    @name("MyIngress.srcRoute_nhop") action srcRoute_nhop_2() {
        {
            if (hdr.srcRoutes[0].isValid()) {
                standard_metadata.egress_spec = (bit<9>)hdr.srcRoutes[0].port;
                __track_egress_spec = true;
            }
            else  {
                bug();
            }
        }
        hdr.srcRoutes.pop_front(1);
    }
    @name("MyIngress.hula_dst") action hula_dst(bit<32> index) {
        meta.index = index;
    }
    @name("MyIngress.hula_set_nhop") action hula_set_nhop(bit<32> index) {
        {
            if (!(index < 32w32))  {
                bug();
            } 
            dstindex_nhop_reg.write(index, (bit<16>)standard_metadata.ingress_port);
        }
    }
    @name("MyIngress.hula_get_nhop") action hula_get_nhop(bit<32> index) {
        {
            if (!(index < 32w32))  {
                bug();
            } 
            dstindex_nhop_reg.read(tmp, index);
        }
        {
            standard_metadata.egress_spec = (bit<9>)tmp;
            __track_egress_spec = true;
        }
    }
    @name("MyIngress.change_best_path_at_dst") action change_best_path_at_dst() {
        if (hdr.hula.isValid()) {
            if (!(meta.index < 32w32))  {
                bug();
            } 
            srcindex_qdepth_reg.write(meta.index, hdr.hula.qdepth);
        }
        else  {
            bug();
        }
        if (hdr.hula.isValid()) {
            if (!(meta.index < 32w32))  {
                bug();
            } 
            srcindex_digest_reg.write(meta.index, hdr.hula.digest);
        }
        else  {
            bug();
        }
    }
    @name("MyIngress.return_hula_to_src") action return_hula_to_src() {
        {
            if (hdr.hula.isValid())  {
                hdr.hula.dir = 1w1;
            } 
            else  {
                bug();
            }
        }
        {
            standard_metadata.egress_spec = standard_metadata.ingress_port;
            __track_egress_spec = true;
        }
    }
    @name("MyIngress.hula_fwd") @instrument_keys() table hula_fwd {
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
    @name("MyIngress.hula_bwd") @instrument_keys() table hula_bwd {
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
    @name("MyIngress.hula_src") @instrument_keys() table hula_src {
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
    @name("MyIngress.hula_nhop") @instrument_keys() table hula_nhop {
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
    @name("MyIngress.dmac") @instrument_keys() table dmac {
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
        __track_egress_spec = false;
        if (hdr.hula.isValid())  {
            if (hdr.hula.isValid())  {
                if (hdr.hula.dir == 1w0)  {
                    switch (hula_fwd.apply().action_run) {
                        hula_dst: {
                            {
                                if (!(meta.index < 32w32))  {
                                    bug();
                                } 
                                srcindex_qdepth_reg.read(old_qdepth, meta.index);
                            }
                            if (hdr.hula.isValid())  {
                                if (old_qdepth > hdr.hula.qdepth) {
                                    change_best_path_at_dst();
                                    return_hula_to_src();
                                }
                                else {
                                    {
                                        if (!(meta.index < 32w32))  {
                                            bug();
                                        } 
                                        srcindex_digest_reg.read(old_digest, meta.index);
                                    }
                                    if (hdr.hula.isValid())  {
                                        if (old_digest == hdr.hula.digest)  {
                                            if (hdr.hula.isValid()) {
                                                if (!(meta.index < 32w32))  {
                                                    bug();
                                                } 
                                                srcindex_qdepth_reg.write(meta.index, hdr.hula.qdepth);
                                            }
                                            else  {
                                                bug();
                                            }
                                        } 
                                    } 
                                    else  {
                                        bug();
                                    }
                                    drop_6();
                                }
                            } 
                            else  {
                                bug();
                            }
                        }
                    }

                } 
                else {
                    hula_bwd.apply();
                    hula_src.apply();
                }
            } 
            else  {
                bug();
            }
        } 
        else  {
            if (hdr.ipv4.isValid()) {
                hash<bit<16>, bit<16>, tuple_0, bit<32>>(flow_hash, HashAlgorithm.crc16, 16w0, tuple_0 {field = hdr.ipv4.srcAddr,field_0 = hdr.ipv4.dstAddr,field_1 = hdr.udp.srcPort}, 32w65536);
                {
                    if (!((bit<32>)flow_hash < 32w65536))  {
                        bug();
                    } 
                    flow_port_reg.read(port_1, (bit<32>)flow_hash);
                }
                if (port_1 == 16w0) {
                    hula_nhop.apply();
                    {
                        if (!((bit<32>)flow_hash < 32w65536))  {
                            bug();
                        } 
                        flow_port_reg.write((bit<32>)flow_hash, (bit<16>)standard_metadata.egress_spec);
                    }
                }
                else {
                    standard_metadata.egress_spec = (bit<9>)port_1;
                    __track_egress_spec = true;
                }
                dmac.apply();
            }
            else  {
                drop_7();
            }
        }
        if (hdr.ipv4.isValid())  {
            update_ttl();
        } 
        if (!__track_egress_spec)  {
            bug();
        } 
    }
}

control MyEgress(inout headers hdr, inout metadata meta, inout standard_metadata_t standard_metadata) {
    apply {
        if (hdr.hula.isValid() || !hdr.hula.isValid())  {
            if (hdr.hula.isValid() && hdr.hula.dir == 1w0)  {
                if (hdr.hula.isValid())  {
                    if (hdr.hula.qdepth < (qdepth_t)standard_metadata.deq_qdepth) {
                        if (hdr.hula.isValid())  {
                            hdr.hula.qdepth = (qdepth_t)standard_metadata.deq_qdepth;
                        } 
                        else  {
                            bug();
                        }
                    }
                } 
                else  {
                    bug();
                }
            } 
        } 
        else  {
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
}
