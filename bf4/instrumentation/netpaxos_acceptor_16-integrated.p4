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

@controlled extern flow_def_fwd_tbl_0 query_fwd_tbl_0(@matchKind("exact") in bit<9> fwd_tbl_0_standard_metadata_ingress_port);
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

@controlled extern flow_def_paxos_tbl_0 query_paxos_tbl_0(@matchKind("exact") in bit<16> paxos_tbl_0_paxos_msgtype);
extern void end_paxos_tbl_0();
enum flow_def_round_tbl_0__action_type_t {
    read_round
}

struct flow_def_round_tbl_0 {
    bool                                hit;
    bool                                reach;
    flow_def_round_tbl_0__action_type_t action_run;
}

@controlled extern flow_def_round_tbl_0 query_round_tbl_0();
extern void end_round_tbl_0();
enum flow_def_drop_tbl_0__action_type_t {
    _drop
}

struct flow_def_drop_tbl_0 {
    bool                               hit;
    bool                               reach;
    flow_def_drop_tbl_0__action_type_t action_run;
}

@controlled extern flow_def_drop_tbl_0 query_drop_tbl_0();
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

parser ParserImpl(mutable_packet packet, out headers hdr, inout metadata meta, inout standard_metadata_t standard_metadata, inout error err) {
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
    flow_def_fwd_tbl_0 fwd_tbl;
    flow_def_round_tbl_0 round_tbl;
    flow_def_paxos_tbl_0 paxos_tbl;
    flow_def_drop_tbl_0 drop_tbl;
    flow_def_fwd_tbl_0 tmp_3;
    flow_def_round_tbl_0 tmp_4;
    flow_def_paxos_tbl_0 tmp_5;
    flow_def_drop_tbl_0 tmp_6;
    @name(".acceptor_id") register<bit<16>>(32w1) acceptor_id_0;
    @name(".proposal_register") register<bit<16>>(32w64000) proposal_register_0;
    @name(".val_register") register<bit<32>>(32w64000) val_register_0;
    @name(".vproposal_register") register<bit<16>>(32w64000) vproposal_register_0;
    apply {
        __track_egress_spec_0 = false;
        if (hdr.ipv4.isValid()) {
            tmp_3 = query_fwd_tbl_0(standard_metadata.ingress_port);
            fwd_tbl = tmp_3;
            if (fwd_tbl.hit) {
                key_match(standard_metadata.ingress_port == fwd_tbl.key_fwd_tbl_0_standard_metadata_ingress_port);
            }
            if (fwd_tbl.action_run == flow_def_fwd_tbl_0__action_type_t.NoAction_5) {
                ;
            }
            else {
                if (fwd_tbl.action_run == flow_def_fwd_tbl_0__action_type_t._drop_2) {
                    angelic_assert(true);
                    standard_metadata.egress_spec = 9w511;
                    __track_egress_spec_0 = true;
                }
                else {
                    if (fwd_tbl.action_run == flow_def_fwd_tbl_0__action_type_t.forward) {
                        angelic_assert(true);
                        standard_metadata.egress_spec = fwd_tbl.forward__port;
                        __track_egress_spec_0 = true;
                    }
                    else {
                        ;
                    }
                }
            }
            end_fwd_tbl_0();
        }
        if (hdr.paxos.isValid()) {
            tmp_4 = query_round_tbl_0();
            round_tbl = tmp_4;
            if (round_tbl.action_run == flow_def_round_tbl_0__action_type_t.read_round) {
                angelic_assert(true);
                if (hdr.paxos.isValid()) {
                    if (hdr.paxos.inst >= 32w64000) {
                        bug();
                    }
                    proposal_register_0.read(meta._local_metadata_proposal0, hdr.paxos.inst);
                }
                else {
                    bug();
                }
            }
            else {
                ;
            }
            end_round_tbl_0();
            if (hdr.paxos.isValid()) {
                if (meta._local_metadata_proposal0 <= hdr.paxos.proposal) {
                    tmp_5 = query_paxos_tbl_0(hdr.paxos.msgtype);
                    paxos_tbl = tmp_5;
                    if (paxos_tbl.hit) {
                        key_match(hdr.paxos.msgtype == paxos_tbl.key_paxos_tbl_0_paxos_msgtype);
                        if (!hdr.paxos.isValid()) {
                            bug();
                        }
                    }
                    if (paxos_tbl.action_run == flow_def_paxos_tbl_0__action_type_t.NoAction_6) {
                        ;
                    }
                    else {
                        if (paxos_tbl.action_run == flow_def_paxos_tbl_0__action_type_t._no_op) {
                            angelic_assert(true);
                        }
                        else {
                            if (paxos_tbl.action_run == flow_def_paxos_tbl_0__action_type_t.handle_phase2a) {
                                angelic_assert(true);
                                if (hdr.paxos.isValid() && hdr.paxos.isValid()) {
                                    if (hdr.paxos.inst >= 32w64000) {
                                        bug();
                                    }
                                    proposal_register_0.write(hdr.paxos.inst, hdr.paxos.proposal);
                                }
                                else {
                                    bug();
                                }
                                if (hdr.paxos.isValid() && hdr.paxos.isValid()) {
                                    if (hdr.paxos.inst >= 32w64000) {
                                        bug();
                                    }
                                    vproposal_register_0.write(hdr.paxos.inst, hdr.paxos.proposal);
                                }
                                else {
                                    bug();
                                }
                                if (hdr.paxos.isValid() && hdr.paxos.isValid()) {
                                    if (hdr.paxos.inst >= 32w64000) {
                                        bug();
                                    }
                                    val_register_0.write(hdr.paxos.inst, hdr.paxos.val);
                                }
                                else {
                                    bug();
                                }
                                if (hdr.paxos.isValid()) {
                                    hdr.paxos.msgtype = 16w4;
                                }
                                else {
                                    bug();
                                }
                                if (hdr.paxos.isValid() && hdr.paxos.isValid()) {
                                    hdr.paxos.vproposal = hdr.paxos.proposal;
                                }
                                else {
                                    bug();
                                }
                                acceptor_id_0.read(hdr.paxos.acpt, 32w0);
                                if (hdr.udp.isValid()) {
                                    hdr.udp.checksum = 16w0;
                                }
                                else {
                                    bug();
                                }
                            }
                            else {
                                if (paxos_tbl.action_run == flow_def_paxos_tbl_0__action_type_t.handle_phase1a) {
                                    angelic_assert(true);
                                    if (hdr.paxos.isValid() && hdr.paxos.isValid()) {
                                        if (hdr.paxos.inst >= 32w64000) {
                                            bug();
                                        }
                                        proposal_register_0.write(hdr.paxos.inst, hdr.paxos.proposal);
                                    }
                                    else {
                                        bug();
                                    }
                                    if (hdr.paxos.isValid()) {
                                        if (hdr.paxos.inst >= 32w64000) {
                                            bug();
                                        }
                                        vproposal_register_0.read(hdr.paxos.vproposal, hdr.paxos.inst);
                                    }
                                    else {
                                        bug();
                                    }
                                    if (hdr.paxos.isValid()) {
                                        if (hdr.paxos.inst >= 32w64000) {
                                            bug();
                                        }
                                        val_register_0.read(hdr.paxos.val, hdr.paxos.inst);
                                    }
                                    else {
                                        bug();
                                    }
                                    if (hdr.paxos.isValid()) {
                                        hdr.paxos.msgtype = 16w2;
                                    }
                                    else {
                                        bug();
                                    }
                                    acceptor_id_0.read(hdr.paxos.acpt, 32w0);
                                    if (hdr.udp.isValid()) {
                                        hdr.udp.checksum = 16w0;
                                    }
                                    else {
                                        bug();
                                    }
                                }
                                else {
                                    ;
                                }
                            }
                        }
                    }
                    end_paxos_tbl_0();
                }
                else {
                    tmp_6 = query_drop_tbl_0();
                    drop_tbl = tmp_6;
                    if (drop_tbl.action_run == flow_def_drop_tbl_0__action_type_t._drop) {
                        angelic_assert(true);
                        standard_metadata.egress_spec = 9w511;
                        __track_egress_spec_0 = true;
                    }
                    else {
                        ;
                    }
                    end_drop_tbl_0();
                }
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

control egress(inout headers hdr, inout metadata meta, inout standard_metadata_t standard_metadata) {
    apply {
    }
}

control DeparserImpl(mutable_packet packet, in headers hdr) {
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
    egress() eg;
    ;
    DeparserImpl() dep;
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
            clone_metas_0._local_metadata_proposal0 = 16w0;
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
    ingress() ig;
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
        hdrs.ipv4.setInvalid();
        hdrs.paxos.setInvalid();
        hdrs.udp.setInvalid();
    }
    ParserImpl() p;
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
        metas._local_metadata_proposal0 = 16w0;
    }
    standard_meta_0.instance_type = PKT_INSTANCE_TYPE_NORMAL_0;
    parse_and_run(pin, metas, standard_meta_0);
}
