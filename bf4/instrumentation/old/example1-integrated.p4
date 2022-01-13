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
    validate_H2,
    _drop_7,
    NoAction_9
}

struct flow_def_t2_0 {
    bool                         hit;
    bool                         reach;
    flow_def_t2_0__action_type_t action_run;
    @matchKind("exact") 
    bit<32>                      key_t2_0_hdr_ipv4_srcAddr;
    @matchKind("exact") 
    bit<32>                      key_t2_0_hdr_ipv4_dstAddr;
}

@controlled extern flow_def_t2_0 query_t2_0(@matchKind("exact") in bit<32> t2_0_hdr_ipv4_srcAddr, @matchKind("exact") in bit<32> t2_0_hdr_ipv4_dstAddr);
extern void end_t2_0();
enum flow_def_t1_0__action_type_t {
    validate_H1,
    _drop_2,
    NoAction_1
}

struct flow_def_t1_0 {
    bool                         hit;
    bool                         reach;
    flow_def_t1_0__action_type_t action_run;
    @matchKind("exact") 
    bit<32>                      key_t1_0_hdr_ipv4_srcAddr;
}

@controlled extern flow_def_t1_0 query_t1_0(@matchKind("exact") in bit<32> t1_0_hdr_ipv4_srcAddr);
extern void end_t1_0();
enum flow_def_send_frame_0__action_type_t {
    rewrite_mac,
    _drop,
    NoAction_0
}

struct flow_def_send_frame_0 {
    bool                                 hit;
    bool                                 reach;
    flow_def_send_frame_0__action_type_t action_run;
    bit<48>                              rewrite_mac__smac;
    @matchKind("exact") 
    bit<9>                               key_send_frame_0_standard_metadata_egress_port;
}

@controlled extern flow_def_send_frame_0 query_send_frame_0(@matchKind("exact") in bit<9> send_frame_0_standard_metadata_egress_port);
extern void end_send_frame_0();
enum flow_def_forward_0__action_type_t {
    set_dmac,
    _drop_9,
    NoAction_12
}

struct flow_def_forward_0 {
    bool                              hit;
    bool                              reach;
    flow_def_forward_0__action_type_t action_run;
    bit<48>                           set_dmac__dmac;
    @matchKind("exact") 
    bit<32>                           key_forward_0_meta_custom_metadata_nhop_ipv4;
}

@controlled extern flow_def_forward_0 query_forward_0(@matchKind("exact") in bit<32> forward_0_meta_custom_metadata_nhop_ipv4);
extern void end_forward_0();
enum flow_def_count_table_0__action_type_t {
    count_action,
    _drop_8,
    NoAction_11
}

struct flow_def_count_table_0 {
    bool                                  hit;
    bool                                  reach;
    flow_def_count_table_0__action_type_t action_run;
    bit<32>                               count_action__idx;
    @matchKind("lpm") 
    bit<32>                               key_count_table_0_hdr_ipv4_srcAddr__val;
    @matchKind("lpm") 
    bit<32>                               key_count_table_0_hdr_ipv4_srcAddr__prefix;
}

@controlled extern flow_def_count_table_0 query_count_table_0(@matchKind("lpm") in bit<32> count_table_0_hdr_ipv4_srcAddr);
extern void end_count_table_0();
enum flow_def_t3_0__action_type_t {
    use_H12,
    NoAction_10
}

struct flow_def_t3_0 {
    bool                         hit;
    bool                         reach;
    flow_def_t3_0__action_type_t action_run;
    @matchKind("exact") 
    bit<32>                      key_t3_0_hdr_ipv4_srcAddr;
    @matchKind("exact") 
    bit<32>                      key_t3_0_hdr_ipv4_dstAddr;
    @matchKind("exact") 
    bit<8>                       key_t3_0_hdr_ipv4_ttl;
}

@controlled extern flow_def_t3_0 query_t3_0(@matchKind("exact") in bit<32> t3_0_hdr_ipv4_srcAddr, @matchKind("exact") in bit<32> t3_0_hdr_ipv4_dstAddr, @matchKind("exact") in bit<8> t3_0_hdr_ipv4_ttl);
extern void end_t3_0();
enum flow_def_ipv4_lpm_0__action_type_t {
    set_nhop,
    _drop_10,
    NoAction_13
}

struct flow_def_ipv4_lpm_0 {
    bool                               hit;
    bool                               reach;
    flow_def_ipv4_lpm_0__action_type_t action_run;
    bit<32>                            set_nhop__nhop_ipv4;
    bit<9>                             set_nhop__port;
    @matchKind("lpm") 
    bit<32>                            key_ipv4_lpm_0_hdr_ipv4_dstAddr__val;
    @matchKind("lpm") 
    bit<32>                            key_ipv4_lpm_0_hdr_ipv4_dstAddr__prefix;
}

@controlled extern flow_def_ipv4_lpm_0 query_ipv4_lpm_0(@matchKind("lpm") in bit<32> ipv4_lpm_0_hdr_ipv4_dstAddr);
extern void end_ipv4_lpm_0();
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
}

parser ParserImpl(mutable_packet packet, out headers hdr, inout metadata meta, inout standard_metadata_t standard_metadata, inout error err) {
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
    flow_def_t1_0 t1;
    flow_def_t2_0 t2;
    flow_def_t3_0 t3;
    flow_def_send_frame_0 send_frame;
    flow_def_t1_0 tmp_6;
    flow_def_t2_0 tmp_7;
    flow_def_t3_0 tmp_8;
    flow_def_send_frame_0 tmp_9;
    apply {
        hdr.ipv4.setInvalid();
        hdr.ethernet.setInvalid();
        tmp_6 = query_t1_0(hdr.ipv4.srcAddr);
        t1 = tmp_6;
        if (t1.hit) {
            key_match(hdr.ipv4.srcAddr == t1.key_t1_0_hdr_ipv4_srcAddr);
            if (!hdr.ipv4.isValid()) {
                bug();
            }
        }
        if (t1.action_run == flow_def_t1_0__action_type_t.NoAction_1) {
            ;
        }
        else {
            if (t1.action_run == flow_def_t1_0__action_type_t._drop_2) {
                angelic_assert(true);
                standard_metadata.egress_spec = 9w511;
            }
            else {
                if (t1.action_run == flow_def_t1_0__action_type_t.validate_H1) {
                    angelic_assert(true);
                    hdr.ipv4.setValid();
                }
                else {
                    ;
                }
            }
        }
        end_t1_0();
        tmp_7 = query_t2_0(hdr.ipv4.srcAddr, hdr.ipv4.dstAddr);
        t2 = tmp_7;
        if (t2.hit) {
            key_match(hdr.ipv4.srcAddr == t2.key_t2_0_hdr_ipv4_srcAddr && hdr.ipv4.dstAddr == t2.key_t2_0_hdr_ipv4_dstAddr);
            if (!hdr.ipv4.isValid()) {
                bug();
            }
            if (!hdr.ipv4.isValid()) {
                bug();
            }
        }
        if (t2.action_run == flow_def_t2_0__action_type_t.NoAction_9) {
            ;
        }
        else {
            if (t2.action_run == flow_def_t2_0__action_type_t._drop_7) {
                angelic_assert(true);
                standard_metadata.egress_spec = 9w511;
            }
            else {
                if (t2.action_run == flow_def_t2_0__action_type_t.validate_H2) {
                    angelic_assert(true);
                    hdr.ethernet.setValid();
                }
                else {
                    ;
                }
            }
        }
        end_t2_0();
        tmp_8 = query_t3_0(hdr.ipv4.srcAddr, hdr.ipv4.dstAddr, hdr.ipv4.ttl);
        t3 = tmp_8;
        if (t3.hit) {
            key_match(hdr.ipv4.srcAddr == t3.key_t3_0_hdr_ipv4_srcAddr && hdr.ipv4.dstAddr == t3.key_t3_0_hdr_ipv4_dstAddr && hdr.ipv4.ttl == t3.key_t3_0_hdr_ipv4_ttl);
            if (!hdr.ipv4.isValid()) {
                bug();
            }
            if (!hdr.ipv4.isValid()) {
                bug();
            }
            if (!hdr.ipv4.isValid()) {
                bug();
            }
        }
        if (t3.action_run == flow_def_t3_0__action_type_t.NoAction_10) {
            ;
        }
        else {
            if (t3.action_run == flow_def_t3_0__action_type_t.use_H12) {
                angelic_assert(true);
                if (hdr.ipv4.isValid() && hdr.ipv4.isValid()) {
                    hdr.ipv4.srcAddr = hdr.ipv4.dstAddr;
                }
                else {
                    bug();
                }
                if (hdr.ethernet.isValid() && hdr.ethernet.isValid()) {
                    hdr.ethernet.srcAddr = hdr.ethernet.dstAddr;
                }
                else {
                    bug();
                }
            }
            else {
                ;
            }
        }
        end_t3_0();
        tmp_9 = query_send_frame_0(standard_metadata.egress_port);
        send_frame = tmp_9;
        if (send_frame.hit) {
            key_match(standard_metadata.egress_port == send_frame.key_send_frame_0_standard_metadata_egress_port);
        }
        if (send_frame.action_run == flow_def_send_frame_0__action_type_t.NoAction_0) {
            ;
        }
        else {
            if (send_frame.action_run == flow_def_send_frame_0__action_type_t._drop) {
                angelic_assert(true);
                standard_metadata.egress_spec = 9w511;
            }
            else {
                if (send_frame.action_run == flow_def_send_frame_0__action_type_t.rewrite_mac) {
                    angelic_assert(true);
                    if (hdr.ethernet.isValid()) {
                        hdr.ethernet.srcAddr = send_frame.rewrite_mac__smac;
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
        end_send_frame_0();
    }
}

control ingress(inout headers hdr, inout metadata meta, inout standard_metadata_t standard_metadata) {
    bool __track_egress_spec_0;
    flow_def_count_table_0 count_table;
    flow_def_ipv4_lpm_0 ipv4_lpm;
    flow_def_forward_0 forward;
    flow_def_count_table_0 tmp_10;
    flow_def_ipv4_lpm_0 tmp_11;
    flow_def_forward_0 tmp_12;
    @name("ingress.ip_src_counter") counter(32w1024, CounterType.packets) ip_src_counter_0;
    apply {
        __track_egress_spec_0 = false;
        tmp_10 = query_count_table_0(hdr.ipv4.srcAddr);
        count_table = tmp_10;
        if (count_table.hit) {
            key_match(hdr.ipv4.srcAddr & (32w1 << count_table.key_count_table_0_hdr_ipv4_srcAddr__prefix) + 32w4294967295 == count_table.key_count_table_0_hdr_ipv4_srcAddr__val & (32w1 << count_table.key_count_table_0_hdr_ipv4_srcAddr__prefix) + 32w4294967295);
            if (!(hdr.ipv4.isValid() || (32w1 << count_table.key_count_table_0_hdr_ipv4_srcAddr__prefix) + 32w4294967295 == 32w0)) {
                bug();
            }
        }
        if (count_table.action_run == flow_def_count_table_0__action_type_t.NoAction_11) {
            ;
        }
        else {
            if (count_table.action_run == flow_def_count_table_0__action_type_t._drop_8) {
                angelic_assert(true);
                standard_metadata.egress_spec = 9w511;
                __track_egress_spec_0 = true;
            }
            else {
                if (count_table.action_run == flow_def_count_table_0__action_type_t.count_action) {
                    angelic_assert(true);
                    if (count_table.count_action__idx >= 32w1024) {
                        bug();
                    }
                    ip_src_counter_0.count(count_table.count_action__idx);
                }
                else {
                    ;
                }
            }
        }
        end_count_table_0();
        tmp_11 = query_ipv4_lpm_0(hdr.ipv4.dstAddr);
        ipv4_lpm = tmp_11;
        if (ipv4_lpm.hit) {
            key_match(hdr.ipv4.dstAddr & (32w1 << ipv4_lpm.key_ipv4_lpm_0_hdr_ipv4_dstAddr__prefix) + 32w4294967295 == ipv4_lpm.key_ipv4_lpm_0_hdr_ipv4_dstAddr__val & (32w1 << ipv4_lpm.key_ipv4_lpm_0_hdr_ipv4_dstAddr__prefix) + 32w4294967295);
            if (!(hdr.ipv4.isValid() || (32w1 << ipv4_lpm.key_ipv4_lpm_0_hdr_ipv4_dstAddr__prefix) + 32w4294967295 == 32w0)) {
                bug();
            }
        }
        if (ipv4_lpm.action_run == flow_def_ipv4_lpm_0__action_type_t.NoAction_13) {
            ;
        }
        else {
            if (ipv4_lpm.action_run == flow_def_ipv4_lpm_0__action_type_t._drop_10) {
                angelic_assert(true);
                standard_metadata.egress_spec = 9w511;
                __track_egress_spec_0 = true;
            }
            else {
                if (ipv4_lpm.action_run == flow_def_ipv4_lpm_0__action_type_t.set_nhop) {
                    angelic_assert(true);
                    meta._custom_metadata_nhop_ipv40 = ipv4_lpm.set_nhop__nhop_ipv4;
                    standard_metadata.egress_spec = ipv4_lpm.set_nhop__port;
                    __track_egress_spec_0 = true;
                    if (hdr.ipv4.isValid() && hdr.ipv4.isValid()) {
                        hdr.ipv4.ttl = hdr.ipv4.ttl + 8w255;
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
        end_ipv4_lpm_0();
        tmp_12 = query_forward_0(meta._custom_metadata_nhop_ipv40);
        forward = tmp_12;
        if (forward.hit) {
            key_match(meta._custom_metadata_nhop_ipv40 == forward.key_forward_0_meta_custom_metadata_nhop_ipv4);
        }
        if (forward.action_run == flow_def_forward_0__action_type_t.NoAction_12) {
            ;
        }
        else {
            if (forward.action_run == flow_def_forward_0__action_type_t._drop_9) {
                angelic_assert(true);
                standard_metadata.egress_spec = 9w511;
                __track_egress_spec_0 = true;
            }
            else {
                if (forward.action_run == flow_def_forward_0__action_type_t.set_dmac) {
                    angelic_assert(true);
                    if (hdr.ethernet.isValid()) {
                        hdr.ethernet.dstAddr = forward.set_dmac__dmac;
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
        end_forward_0();
        if (!__track_egress_spec_0) {
            bug();
        }
    }
}

control DeparserImpl(mutable_packet packet, in headers hdr) {
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
            clone_metas_0._custom_metadata_nhop_ipv40 = 32w0;
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
        hdrs.tcp.setInvalid();
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
        metas._custom_metadata_nhop_ipv40 = 32w0;
    }
    standard_meta_0.instance_type = PKT_INSTANCE_TYPE_NORMAL_0;
    parse_and_run(pin, metas, standard_meta_0);
}
