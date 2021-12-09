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
enum flow_def_forward_0__action_type_t {
    set_dmac,
    _drop_6,
    NoAction_10
}

struct flow_def_forward_0 {
    bool                              hit;
    bool                              reach;
    flow_def_forward_0__action_type_t action_run;
    bit<48>                           set_dmac__dmac;
    @matchKind("exact") 
    bit<32>                           key_forward_0_ingress_metadata_nhop_ipv4;
}

@controlled extern flow_def_forward_0 query_forward_0(@matchKind("exact") in bit<32> forward_0_ingress_metadata_nhop_ipv4);
extern void end_forward_0();
enum flow_def_flowlet_0__action_type_t {
    lookup_flowlet_map
}

struct flow_def_flowlet_0 {
    bool                              hit;
    bool                              reach;
    flow_def_flowlet_0__action_type_t action_run;
}

@controlled extern flow_def_flowlet_0 query_flowlet_0();
extern void end_flowlet_0();
enum flow_def_ecmp_nhop_0__action_type_t {
    _drop_5,
    set_nhop
}

struct flow_def_ecmp_nhop_0 {
    bool                                hit;
    bool                                reach;
    flow_def_ecmp_nhop_0__action_type_t action_run;
    bit<32>                             set_nhop__nhop_ipv4;
    bit<9>                              set_nhop__port;
    @matchKind("exact") 
    bit<14>                             key_ecmp_nhop_0_ingress_metadata_ecmp_offset;
}

@controlled extern flow_def_ecmp_nhop_0 query_ecmp_nhop_0(@matchKind("exact") in bit<14> ecmp_nhop_0_ingress_metadata_ecmp_offset);
extern void end_ecmp_nhop_0();
enum flow_def_new_flowlet_0__action_type_t {
    update_flowlet_id
}

struct flow_def_new_flowlet_0 {
    bool                                  hit;
    bool                                  reach;
    flow_def_new_flowlet_0__action_type_t action_run;
}

@controlled extern flow_def_new_flowlet_0 query_new_flowlet_0();
extern void end_new_flowlet_0();
enum flow_def_ecmp_group_0__action_type_t {
    _drop_2,
    set_ecmp_select,
    NoAction_1
}

struct flow_def_ecmp_group_0 {
    bool                                 hit;
    bool                                 reach;
    flow_def_ecmp_group_0__action_type_t action_run;
    bit<8>                               set_ecmp_select__ecmp_base;
    bit<8>                               set_ecmp_select__ecmp_count;
    @matchKind("lpm") 
    bit<32>                              key_ecmp_group_0_ipv4_dstAddr__val;
    @matchKind("lpm") 
    bit<32>                              key_ecmp_group_0_ipv4_dstAddr__prefix;
}

@controlled extern flow_def_ecmp_group_0 query_ecmp_group_0(@matchKind("lpm") in bit<32> ecmp_group_0_ipv4_dstAddr);
extern void end_ecmp_group_0();
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
extern void key_match(in bool condition);
extern void angelic_assert(in bool condition);
extern void bug();

#include <core.p4>

#include <v1model.p4>

struct ingress_metadata_t {
    bit<32> flow_ipg;
    bit<13> flowlet_map_index;
    bit<16> flowlet_id;
    bit<32> flowlet_lasttime;
    bit<14> ecmp_offset;
    bit<32> nhop_ipv4;
}

struct intrinsic_metadata_t {
    bit<48> ingress_global_timestamp;
    bit<32> lf_field_list;
    bit<16> mcast_grp;
    bit<16> egress_rid;
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
    bit<32> _ingress_metadata_flow_ipg0;
    bit<13> _ingress_metadata_flowlet_map_index1;
    bit<16> _ingress_metadata_flowlet_id2;
    bit<32> _ingress_metadata_flowlet_lasttime3;
    bit<14> _ingress_metadata_ecmp_offset4;
    bit<32> _ingress_metadata_nhop_ipv45;
    bit<48> _intrinsic_metadata_ingress_global_timestamp6;
    bit<32> _intrinsic_metadata_lf_field_list7;
    bit<16> _intrinsic_metadata_mcast_grp8;
    bit<16> _intrinsic_metadata_egress_rid9;
}

struct headers {
    @name(".ethernet") 
    ethernet_t ethernet;
    @name(".ipv4") 
    ipv4_t     ipv4;
    @name(".tcp") 
    tcp_t      tcp;
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
            8w6: parse_tcp;
            default: accept;
        }
    }
    @name(".parse_tcp") state parse_tcp {
        packet.extract<tcp_t>(hdr.tcp);
        transition accept;
    }
    @name(".start") state start {
        transition parse_ethernet;
    }
}

control egress(inout headers hdr, inout metadata meta, inout standard_metadata_t standard_metadata) {
    flow_def_send_frame_0 send_frame;
    flow_def_send_frame_0 tmp_5;
    apply {
        tmp_5 = query_send_frame_0(standard_metadata.egress_port);
        send_frame = tmp_5;
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

struct tuple_0 {
    bit<32> field;
    bit<32> field_0;
    bit<8>  field_1;
    bit<16> field_2;
    bit<16> field_3;
    bit<16> field_4;
}

struct tuple_1 {
    bit<32> field_5;
    bit<32> field_6;
    bit<8>  field_7;
    bit<16> field_8;
    bit<16> field_9;
}

control ingress(inout headers hdr, inout metadata meta, inout standard_metadata_t standard_metadata) {
    bool __track_egress_spec_0;
    flow_def_flowlet_0 flowlet;
    flow_def_new_flowlet_0 new_flowlet;
    flow_def_ecmp_group_0 ecmp_group;
    flow_def_ecmp_nhop_0 ecmp_nhop;
    flow_def_forward_0 forward;
    flow_def_flowlet_0 tmp_6;
    flow_def_new_flowlet_0 tmp_7;
    flow_def_ecmp_group_0 tmp_8;
    flow_def_ecmp_nhop_0 tmp_9;
    flow_def_forward_0 tmp_10;
    @name("ingress.flowlet_id") register<bit<16>>(32w8192) flowlet_id_0;
    @name("ingress.flowlet_lasttime") register<bit<32>>(32w8192) flowlet_lasttime_0;
    apply {
        __track_egress_spec_0 = false;
        tmp_6 = query_flowlet_0();
        flowlet = tmp_6;
        if (flowlet.action_run == flow_def_flowlet_0__action_type_t.lookup_flowlet_map) {
            angelic_assert(true);
            hash<bit<13>, bit<13>, tuple_1, bit<26>>(meta._ingress_metadata_flowlet_map_index1, HashAlgorithm.crc16, 13w0, tuple_1 {field_5 = hdr.ipv4.srcAddr,field_6 = hdr.ipv4.dstAddr,field_7 = hdr.ipv4.protocol,field_8 = hdr.tcp.srcPort,field_9 = hdr.tcp.dstPort}, 26w13);
            if ((bit<32>)meta._ingress_metadata_flowlet_map_index1 >= 32w8192) {
                bug();
            }
            flowlet_id_0.read(meta._ingress_metadata_flowlet_id2, (bit<32>)meta._ingress_metadata_flowlet_map_index1);
            if ((bit<32>)meta._ingress_metadata_flowlet_map_index1 >= 32w8192) {
                bug();
            }
            flowlet_lasttime_0.read(meta._ingress_metadata_flowlet_lasttime3, (bit<32>)meta._ingress_metadata_flowlet_map_index1);
            meta._ingress_metadata_flow_ipg0 = (bit<32>)meta._intrinsic_metadata_ingress_global_timestamp6 - meta._ingress_metadata_flowlet_lasttime3;
            if ((bit<32>)meta._ingress_metadata_flowlet_map_index1 >= 32w8192) {
                bug();
            }
            flowlet_lasttime_0.write((bit<32>)meta._ingress_metadata_flowlet_map_index1, (bit<32>)meta._intrinsic_metadata_ingress_global_timestamp6);
        }
        else {
            ;
        }
        end_flowlet_0();
        if (meta._ingress_metadata_flow_ipg0 > 32w50000) {
            tmp_7 = query_new_flowlet_0();
            new_flowlet = tmp_7;
            if (new_flowlet.action_run == flow_def_new_flowlet_0__action_type_t.update_flowlet_id) {
                angelic_assert(true);
                meta._ingress_metadata_flowlet_id2 = meta._ingress_metadata_flowlet_id2 + 16w1;
                if ((bit<32>)meta._ingress_metadata_flowlet_map_index1 >= 32w8192) {
                    bug();
                }
                flowlet_id_0.write((bit<32>)meta._ingress_metadata_flowlet_map_index1, meta._ingress_metadata_flowlet_id2);
            }
            else {
                ;
            }
            end_new_flowlet_0();
        }
        tmp_8 = query_ecmp_group_0(hdr.ipv4.dstAddr);
        ecmp_group = tmp_8;
        if (ecmp_group.hit) {
            key_match(hdr.ipv4.dstAddr & (32w1 << ecmp_group.key_ecmp_group_0_ipv4_dstAddr__prefix) + 32w4294967295 == ecmp_group.key_ecmp_group_0_ipv4_dstAddr__val & (32w1 << ecmp_group.key_ecmp_group_0_ipv4_dstAddr__prefix) + 32w4294967295);
            if (!(hdr.ipv4.isValid() || (32w1 << ecmp_group.key_ecmp_group_0_ipv4_dstAddr__prefix) + 32w4294967295 == 32w0)) {
                bug();
            }
        }
        if (ecmp_group.action_run == flow_def_ecmp_group_0__action_type_t.NoAction_1) {
            ;
        }
        else {
            if (ecmp_group.action_run == flow_def_ecmp_group_0__action_type_t.set_ecmp_select) {
                angelic_assert(true);
                hash<bit<14>, bit<10>, tuple_0, bit<20>>(meta._ingress_metadata_ecmp_offset4, HashAlgorithm.crc16, (bit<10>)ecmp_group.set_ecmp_select__ecmp_base, tuple_0 {field = hdr.ipv4.srcAddr,field_0 = hdr.ipv4.dstAddr,field_1 = hdr.ipv4.protocol,field_2 = hdr.tcp.srcPort,field_3 = hdr.tcp.dstPort,field_4 = meta._ingress_metadata_flowlet_id2}, (bit<20>)ecmp_group.set_ecmp_select__ecmp_count);
            }
            else {
                if (ecmp_group.action_run == flow_def_ecmp_group_0__action_type_t._drop_2) {
                    angelic_assert(true);
                    standard_metadata.egress_spec = 9w511;
                    __track_egress_spec_0 = true;
                }
                else {
                    ;
                }
            }
        }
        end_ecmp_group_0();
        tmp_9 = query_ecmp_nhop_0(meta._ingress_metadata_ecmp_offset4);
        ecmp_nhop = tmp_9;
        if (ecmp_nhop.hit) {
            key_match(meta._ingress_metadata_ecmp_offset4 == ecmp_nhop.key_ecmp_nhop_0_ingress_metadata_ecmp_offset);
        }
        if (ecmp_nhop.action_run == flow_def_ecmp_nhop_0__action_type_t.set_nhop) {
            angelic_assert(true);
            meta._ingress_metadata_nhop_ipv45 = ecmp_nhop.set_nhop__nhop_ipv4;
            standard_metadata.egress_spec = ecmp_nhop.set_nhop__port;
            __track_egress_spec_0 = true;
            if (hdr.ipv4.isValid() && hdr.ipv4.isValid()) {
                hdr.ipv4.ttl = hdr.ipv4.ttl + 8w255;
            }
            else {
                bug();
            }
        }
        else {
            if (ecmp_nhop.action_run == flow_def_ecmp_nhop_0__action_type_t._drop_5) {
                angelic_assert(true);
                standard_metadata.egress_spec = 9w511;
                __track_egress_spec_0 = true;
            }
            else {
                ;
            }
        }
        end_ecmp_nhop_0();
        tmp_10 = query_forward_0(meta._ingress_metadata_nhop_ipv45);
        forward = tmp_10;
        if (forward.hit) {
            key_match(meta._ingress_metadata_nhop_ipv45 == forward.key_forward_0_ingress_metadata_nhop_ipv4);
        }
        if (forward.action_run == flow_def_forward_0__action_type_t.NoAction_10) {
            ;
        }
        else {
            if (forward.action_run == flow_def_forward_0__action_type_t._drop_6) {
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

struct tuple_2 {
    bit<4>  field_10;
    bit<4>  field_11;
    bit<8>  field_12;
    bit<16> field_13;
    bit<16> field_14;
    bit<3>  field_15;
    bit<13> field_16;
    bit<8>  field_17;
    bit<8>  field_18;
    bit<32> field_19;
    bit<32> field_20;
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
            clone_metas_0._ingress_metadata_flow_ipg0 = 32w0;
            clone_metas_0._ingress_metadata_flowlet_map_index1 = 13w0;
            clone_metas_0._ingress_metadata_flowlet_id2 = 16w0;
            clone_metas_0._ingress_metadata_flowlet_lasttime3 = 32w0;
            clone_metas_0._ingress_metadata_ecmp_offset4 = 14w0;
            clone_metas_0._ingress_metadata_nhop_ipv45 = 32w0;
            clone_metas_0._intrinsic_metadata_ingress_global_timestamp6 = 48w0;
            clone_metas_0._intrinsic_metadata_lf_field_list7 = 32w0;
            clone_metas_0._intrinsic_metadata_mcast_grp8 = 16w0;
            clone_metas_0._intrinsic_metadata_egress_rid9 = 16w0;
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
        metas._ingress_metadata_flow_ipg0 = 32w0;
        metas._ingress_metadata_flowlet_map_index1 = 13w0;
        metas._ingress_metadata_flowlet_id2 = 16w0;
        metas._ingress_metadata_flowlet_lasttime3 = 32w0;
        metas._ingress_metadata_ecmp_offset4 = 14w0;
        metas._ingress_metadata_nhop_ipv45 = 32w0;
        metas._intrinsic_metadata_ingress_global_timestamp6 = 48w0;
        metas._intrinsic_metadata_lf_field_list7 = 32w0;
        metas._intrinsic_metadata_mcast_grp8 = 16w0;
        metas._intrinsic_metadata_egress_rid9 = 16w0;
    }
    standard_meta_0.instance_type = PKT_INSTANCE_TYPE_NORMAL_0;
    parse_and_run(pin, metas, standard_meta_0);
}
