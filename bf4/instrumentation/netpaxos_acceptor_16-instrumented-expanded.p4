enum flow_def_fwd_tbl_0__action_type_t {
    forward,
    _drop_2,
    NoAction_5
}

struct flow_def_fwd_tbl_0 {
    bool                              hit;
    bool                              reach;
    flow_def_fwd_tbl_0__action_type_t action_run;
    bit<9>                            forward__port;
    @matchKind("exact") 
    bit<9>                            key_fwd_tbl_0_standard_metadata_ingress_port;
}

@controlled() extern flow_def_fwd_tbl_0 query_fwd_tbl_0(@matchKind("exact") in bit<9> fwd_tbl_0_standard_metadata_ingress_port);
extern void end_fwd_tbl_0();
enum flow_def_paxos_tbl_0__action_type_t {
    handle_phase1a,
    handle_phase2a,
    _no_op,
    NoAction_6
}

struct flow_def_paxos_tbl_0 {
    bool                                hit;
    bool                                reach;
    flow_def_paxos_tbl_0__action_type_t action_run;
    @matchKind("exact") 
    bit<16>                             key_paxos_tbl_0_paxos_msgtype;
}

@controlled() extern flow_def_paxos_tbl_0 query_paxos_tbl_0(@matchKind("exact") in bit<16> paxos_tbl_0_paxos_msgtype);
extern void end_paxos_tbl_0();
enum flow_def_round_tbl_0__action_type_t {
    read_round
}

struct flow_def_round_tbl_0 {
    bool                                hit;
    bool                                reach;
    flow_def_round_tbl_0__action_type_t action_run;
}

@controlled() extern flow_def_round_tbl_0 query_round_tbl_0();
extern void end_round_tbl_0();
enum flow_def_drop_tbl_0__action_type_t {
    _drop
}

struct flow_def_drop_tbl_0 {
    bool                               hit;
    bool                               reach;
    flow_def_drop_tbl_0__action_type_t action_run;
}

@controlled() extern flow_def_drop_tbl_0 query_drop_tbl_0();
extern void end_drop_tbl_0();
extern void key_match(in bool condition);
extern void angelic_assert(in bool condition);
extern void bug();

#include <core.p4>

#include <v1model.p4>

struct local_metadata_t {
    bit<16> proposal;
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
    bit<32> src;
    bit<32> dst;
}

header paxos_t {
    bit<32> inst;
    bit<16> proposal;
    bit<16> vproposal;
    bit<16> acpt;
    bit<16> msgtype;
    bit<32> val;
    bit<32> fsh;
    bit<32> fsl;
    bit<32> feh;
    bit<32> fel;
    bit<32> csh;
    bit<32> csl;
    bit<32> ceh;
    bit<32> cel;
    bit<32> ash;
    bit<32> asl;
    bit<32> aeh;
    bit<32> ael;
}

header udp_t {
    bit<16> srcPort;
    bit<16> dstPort;
    bit<16> length_;
    bit<16> checksum;
}

struct metadata {
    bit<16> _local_metadata_proposal0;
}

struct headers {
    @name(".ethernet") 
    ethernet_t ethernet;
    @name(".ipv4") 
    ipv4_t     ipv4;
    @name(".paxos") 
    paxos_t    paxos;
    @name(".udp") 
    udp_t      udp;
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
            8w0x11: parse_udp;
            default: accept;
        }
    }
    @name(".parse_paxos") state parse_paxos {
        packet.extract<paxos_t>(hdr.paxos);
        transition accept;
    }
    @name(".parse_udp") state parse_udp {
        packet.extract<udp_t>(hdr.udp);
        transition select(hdr.udp.dstPort) {
            16w0x8888: parse_paxos;
            default: accept;
        }
    }
    @name(".start") state start {
        transition parse_ethernet;
    }
}

control ingress(inout headers hdr, inout metadata meta, inout standard_metadata_t standard_metadata) {
    bool __track_egress_spec_0;
    @name(".acceptor_id") register<bit<16>>(32w1) acceptor_id_0;
    @name(".proposal_register") register<bit<16>>(32w64000) proposal_register_0;
    @name(".val_register") register<bit<32>>(32w64000) val_register_0;
    @name(".vproposal_register") register<bit<16>>(32w64000) vproposal_register_0;
    apply {
        __track_egress_spec_0 = false;
        if (hdr.ipv4.isValid()) {
            flow_def_fwd_tbl_0 fwd_tbl;
            fwd_tbl = query_fwd_tbl_0(standard_metadata.ingress_port);
            if (fwd_tbl.hit) {
                key_match(standard_metadata.ingress_port == fwd_tbl.key_fwd_tbl_0_standard_metadata_ingress_port);
            }
            if (fwd_tbl.action_run == flow_def_fwd_tbl_0__action_type_t.NoAction_5) {
            }
            else  {
                if (fwd_tbl.action_run == flow_def_fwd_tbl_0__action_type_t._drop_2) {
                    angelic_assert(true);
                    {
                        standard_metadata.egress_spec = 9w511;
                        __track_egress_spec_0 = true;
                    }
                }
                else  {
                    if (fwd_tbl.action_run == flow_def_fwd_tbl_0__action_type_t.forward) {
                        angelic_assert(true);
                        {
                            standard_metadata.egress_spec = fwd_tbl.forward__port;
                            __track_egress_spec_0 = true;
                        }
                    }
                    else  {
                        ;
                    }
                }
            }
            end_fwd_tbl_0();
        }
        if (hdr.paxos.isValid()) {
            {
                flow_def_round_tbl_0 round_tbl;
                round_tbl = query_round_tbl_0();
                ;
                if (round_tbl.action_run == flow_def_round_tbl_0__action_type_t.read_round) {
                    angelic_assert(true);
                    {
                        if (hdr.paxos.isValid()) {
                            if (hdr.paxos.inst >= 32w64000)  {
                                bug();
                            } 
                            proposal_register_0.read(meta._local_metadata_proposal0, hdr.paxos.inst);
                        }
                        else  {
                            bug();
                        }
                    }
                }
                else  {
                    ;
                }
                end_round_tbl_0();
            }
            if (hdr.paxos.isValid())  {
                if (meta._local_metadata_proposal0 <= hdr.paxos.proposal) {
                    flow_def_paxos_tbl_0 paxos_tbl;
                    paxos_tbl = query_paxos_tbl_0(hdr.paxos.msgtype);
                    if (paxos_tbl.hit) {
                        key_match(hdr.paxos.msgtype == paxos_tbl.key_paxos_tbl_0_paxos_msgtype);
                        if (!hdr.paxos.isValid())  {
                            bug();
                        } 
                    }
                    if (paxos_tbl.action_run == flow_def_paxos_tbl_0__action_type_t.NoAction_6) {
                    }
                    else  {
                        if (paxos_tbl.action_run == flow_def_paxos_tbl_0__action_type_t._no_op) {
                            angelic_assert(true);
                            {
                            }
                        }
                        else  {
                            if (paxos_tbl.action_run == flow_def_paxos_tbl_0__action_type_t.handle_phase2a) {
                                angelic_assert(true);
                                {
                                    if (hdr.paxos.isValid() && hdr.paxos.isValid()) {
                                        if (hdr.paxos.inst >= 32w64000)  {
                                            bug();
                                        } 
                                        proposal_register_0.write(hdr.paxos.inst, hdr.paxos.proposal);
                                    }
                                    else  {
                                        bug();
                                    }
                                    if (hdr.paxos.isValid() && hdr.paxos.isValid()) {
                                        if (hdr.paxos.inst >= 32w64000)  {
                                            bug();
                                        } 
                                        vproposal_register_0.write(hdr.paxos.inst, hdr.paxos.proposal);
                                    }
                                    else  {
                                        bug();
                                    }
                                    if (hdr.paxos.isValid() && hdr.paxos.isValid()) {
                                        if (hdr.paxos.inst >= 32w64000)  {
                                            bug();
                                        } 
                                        val_register_0.write(hdr.paxos.inst, hdr.paxos.val);
                                    }
                                    else  {
                                        bug();
                                    }
                                    if (hdr.paxos.isValid())  {
                                        hdr.paxos.msgtype = 16w4;
                                    } 
                                    else  {
                                        bug();
                                    }
                                    if (hdr.paxos.isValid() && hdr.paxos.isValid())  {
                                        hdr.paxos.vproposal = hdr.paxos.proposal;
                                    } 
                                    else  {
                                        bug();
                                    }
                                    acceptor_id_0.read(hdr.paxos.acpt, 32w0);
                                    if (hdr.udp.isValid())  {
                                        hdr.udp.checksum = 16w0;
                                    } 
                                    else  {
                                        bug();
                                    }
                                }
                            }
                            else  {
                                if (paxos_tbl.action_run == flow_def_paxos_tbl_0__action_type_t.handle_phase1a) {
                                    angelic_assert(true);
                                    {
                                        if (hdr.paxos.isValid() && hdr.paxos.isValid()) {
                                            if (hdr.paxos.inst >= 32w64000)  {
                                                bug();
                                            } 
                                            proposal_register_0.write(hdr.paxos.inst, hdr.paxos.proposal);
                                        }
                                        else  {
                                            bug();
                                        }
                                        if (hdr.paxos.isValid()) {
                                            if (hdr.paxos.inst >= 32w64000)  {
                                                bug();
                                            } 
                                            vproposal_register_0.read(hdr.paxos.vproposal, hdr.paxos.inst);
                                        }
                                        else  {
                                            bug();
                                        }
                                        if (hdr.paxos.isValid()) {
                                            if (hdr.paxos.inst >= 32w64000)  {
                                                bug();
                                            } 
                                            val_register_0.read(hdr.paxos.val, hdr.paxos.inst);
                                        }
                                        else  {
                                            bug();
                                        }
                                        if (hdr.paxos.isValid())  {
                                            hdr.paxos.msgtype = 16w2;
                                        } 
                                        else  {
                                            bug();
                                        }
                                        acceptor_id_0.read(hdr.paxos.acpt, 32w0);
                                        if (hdr.udp.isValid())  {
                                            hdr.udp.checksum = 16w0;
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
                    }
                    end_paxos_tbl_0();
                }
                else {
                    flow_def_drop_tbl_0 drop_tbl;
                    drop_tbl = query_drop_tbl_0();
                    ;
                    if (drop_tbl.action_run == flow_def_drop_tbl_0__action_type_t._drop) {
                        angelic_assert(true);
                        {
                            standard_metadata.egress_spec = 9w511;
                            __track_egress_spec_0 = true;
                        }
                    }
                    else  {
                        ;
                    }
                    end_drop_tbl_0();
                }
            } 
            else  {
                bug();
            }
        }
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
        packet.emit<ipv4_t>(hdr.ipv4);
        packet.emit<udp_t>(hdr.udp);
        packet.emit<paxos_t>(hdr.paxos);
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
