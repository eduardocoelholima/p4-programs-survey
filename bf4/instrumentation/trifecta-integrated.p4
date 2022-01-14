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
enum flow_def_t2_0__action_type_t {
    validate_h2,
    drop_4,
    NoAction_4
}

struct flow_def_t2_0 {
    bool                         hit;
    bool                         reach;
    flow_def_t2_0__action_type_t action_run;
    bit<16>                      validate_h2__value;
    @matchKind("exact") 
    bit<16>                      key_t2_0_hdr_h0_value;
}

@controlled extern flow_def_t2_0 query_t2_0(@matchKind("exact") in bit<16> t2_0_hdr_h0_value);
extern void end_t2_0();
enum flow_def_t1_0__action_type_t {
    validate_h1,
    drop_1,
    NoAction_0
}

struct flow_def_t1_0 {
    bool                         hit;
    bool                         reach;
    flow_def_t1_0__action_type_t action_run;
    bit<16>                      validate_h1__value;
    @matchKind("exact") 
    bit<16>                      key_t1_0_hdr_h0_value;
}

@controlled extern flow_def_t1_0 query_t1_0(@matchKind("exact") in bit<16> t1_0_hdr_h0_value);
extern void end_t1_0();
enum flow_def_t3_0__action_type_t {
    validate_h3,
    drop_5,
    NoAction_5
}

struct flow_def_t3_0 {
    bool                         hit;
    bool                         reach;
    flow_def_t3_0__action_type_t action_run;
    bit<16>                      validate_h3__value;
    @matchKind("exact") 
    bit<16>                      key_t3_0_hdr_h0_value;
}

@controlled extern flow_def_t3_0 query_t3_0(@matchKind("exact") in bit<16> t3_0_hdr_h0_value);
extern void end_t3_0();
extern void key_match(in bool condition);
extern void angelic_assert(in bool condition);
extern void bug();

#include <core.p4>

#include <v1model.p4>

struct ghost_t {
    bit<1> used;
}

header h_t {
    bit<16> value;
}

struct metadata {
    bit<1> _ghost_used0;
}

struct headers {
    h_t h0;
    h_t h1;
    h_t h2;
    h_t h3;
    h_t h4;
}

parser ParserImpl(mutable_packet packet, out headers hdr, inout metadata meta, inout standard_metadata_t standard_metadata, inout error err) {
    @name(".start") state start {
        packet.extract<h_t>(hdr.h0);
        transition accept;
    }
}

control ingress(inout headers hdr, inout metadata meta, inout standard_metadata_t standard_metadata) {
    bool __track_egress_spec_0;
    flow_def_t1_0 t1;
    flow_def_t2_0 t2;
    flow_def_t3_0 t3;
    flow_def_t1_0 tmp_2;
    flow_def_t2_0 tmp_3;
    flow_def_t3_0 tmp_4;
    apply {
        meta._ghost_used0 = 1w0;
        hdr.h1.setInvalid();
        hdr.h2.setInvalid();
        hdr.h3.setInvalid();
        hdr.h4.setInvalid();
        tmp_2 = query_t1_0(hdr.h0.value);
        t1 = tmp_2;
        if (t1.hit) {
            key_match(hdr.h0.value == t1.key_t1_0_hdr_h0_value);
            if (!hdr.h0.isValid()) {
                bug();
            }
        }
        if (t1.action_run == flow_def_t1_0__action_type_t.NoAction_0) {
            ;
        }
        else {
            if (t1.action_run == flow_def_t1_0__action_type_t.drop_1) {
                angelic_assert(true);
            }
            else {
                if (t1.action_run == flow_def_t1_0__action_type_t.validate_h1) {
                    angelic_assert(true);
                    hdr.h1.setValid();
                    if (hdr.h1.isValid()) {
                        hdr.h1.value = t1.validate_h1__value;
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
        end_t1_0();
        tmp_3 = query_t2_0(hdr.h0.value);
        t2 = tmp_3;
        if (t2.hit) {
            key_match(hdr.h0.value == t2.key_t2_0_hdr_h0_value);
            if (!hdr.h0.isValid()) {
                bug();
            }
        }
        if (t2.action_run == flow_def_t2_0__action_type_t.NoAction_4) {
            ;
        }
        else {
            if (t2.action_run == flow_def_t2_0__action_type_t.drop_4) {
                angelic_assert(true);
            }
            else {
                if (t2.action_run == flow_def_t2_0__action_type_t.validate_h2) {
                    angelic_assert(true);
                    if (hdr.h2.isValid()) {
                        hdr.h2.value = t2.validate_h2__value;
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
        end_t2_0();
        tmp_4 = query_t3_0(hdr.h0.value);
        t3 = tmp_4;
        if (t3.hit) {
            key_match(hdr.h0.value == t3.key_t3_0_hdr_h0_value);
            if (!hdr.h0.isValid()) {
                bug();
            }
        }
        if (t3.action_run == flow_def_t3_0__action_type_t.NoAction_5) {
            ;
        }
        else {
            if (t3.action_run == flow_def_t3_0__action_type_t.drop_5) {
                angelic_assert(true);
            }
            else {
                if (t3.action_run == flow_def_t3_0__action_type_t.validate_h3) {
                    angelic_assert(true);
                    hdr.h3.setValid();
                    if (hdr.h3.isValid()) {
                        hdr.h3.value = t3.validate_h3__value;
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
        end_t3_0();
        standard_metadata.egress_spec = 9w511;
        __track_egress_spec_0 = true;
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
            clone_metas_0._ghost_used0 = 1w0;
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
        hdrs.h0.setInvalid();
        hdrs.h1.setInvalid();
        hdrs.h2.setInvalid();
        hdrs.h3.setInvalid();
        hdrs.h4.setInvalid();
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
        metas._ghost_used0 = 1w0;
    }
    standard_meta_0.instance_type = PKT_INSTANCE_TYPE_NORMAL_0;
    parse_and_run(pin, metas, standard_meta_0);
}
