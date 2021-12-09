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
enum flow_def_if_info_0__action_type_t {
    _drop_6,
    set_if_info
}

struct flow_def_if_info_0 {
    bool                              hit;
    bool                              reach;
    flow_def_if_info_0__action_type_t action_run;
    bit<32>                           set_if_info__ipv4_addr;
    bit<48>                           set_if_info__mac_addr;
    bit<1>                            set_if_info__is_ext;
    @matchKind("exact") 
    bit<8>                            key_if_info_0_meta_if_index;
}

@controlled extern flow_def_if_info_0 query_if_info_0(@matchKind("exact") in bit<8> if_info_0_meta_if_index);
extern void end_if_info_0();
enum flow_def_send_to_cpu_0__action_type_t {
    do_cpu_encap
}

struct flow_def_send_to_cpu_0 {
    bool                                  hit;
    bool                                  reach;
    flow_def_send_to_cpu_0__action_type_t action_run;
}

@controlled extern flow_def_send_to_cpu_0 query_send_to_cpu_0();
extern void end_send_to_cpu_0();
enum flow_def_forward_0__action_type_t {
    set_dmac,
    _drop_2,
    NoAction_8
}

struct flow_def_forward_0 {
    bool                              hit;
    bool                              reach;
    flow_def_forward_0__action_type_t action_run;
    bit<48>                           set_dmac__dmac;
    @matchKind("exact") 
    bit<32>                           key_forward_0_meta_nhop_ipv4;
}

@controlled extern flow_def_forward_0 query_forward_0(@matchKind("exact") in bit<32> forward_0_meta_nhop_ipv4);
extern void end_forward_0();
enum flow_def_send_frame_0__action_type_t {
    do_rewrites,
    _drop,
    NoAction_0
}

struct flow_def_send_frame_0 {
    bool                                 hit;
    bool                                 reach;
    flow_def_send_frame_0__action_type_t action_run;
    bit<48>                              do_rewrites__smac;
    @matchKind("exact") 
    bit<9>                               key_send_frame_0_standard_metadata_egress_port;
}

@controlled extern flow_def_send_frame_0 query_send_frame_0(@matchKind("exact") in bit<9> send_frame_0_standard_metadata_egress_port);
extern void end_send_frame_0();
enum flow_def_nat_0__action_type_t {
    _drop_8,
    nat_miss_int_to_ext,
    nat_miss_ext_to_int,
    nat_hit_int_to_ext,
    nat_hit_ext_to_int,
    nat_no_nat,
    NoAction_11
}

struct flow_def_nat_0 {
    bool                          hit;
    bool                          reach;
    flow_def_nat_0__action_type_t action_run;
    bit<32>                       nat_hit_int_to_ext__srcAddr;
    bit<16>                       nat_hit_int_to_ext__srcPort;
    bit<32>                       nat_hit_ext_to_int__dstAddr;
    bit<16>                       nat_hit_ext_to_int__dstPort;
    @matchKind("exact") 
    bit<1>                        key_nat_0_meta_is_ext_if;
    @matchKind("exact") 
    bool                          key_nat_0_ipv4__valid_;
    @matchKind("exact") 
    bool                          key_nat_0_tcp__valid_;
    @matchKind("ternary") 
    bit<32>                       key_nat_0_ipv4_srcAddr__val;
    @matchKind("ternary") 
    bit<32>                       key_nat_0_ipv4_srcAddr__mask;
    @matchKind("ternary") 
    bit<32>                       key_nat_0_ipv4_dstAddr__val;
    @matchKind("ternary") 
    bit<32>                       key_nat_0_ipv4_dstAddr__mask;
    @matchKind("ternary") 
    bit<16>                       key_nat_0_tcp_srcPort__val;
    @matchKind("ternary") 
    bit<16>                       key_nat_0_tcp_srcPort__mask;
    @matchKind("ternary") 
    bit<16>                       key_nat_0_tcp_dstPort__val;
    @matchKind("ternary") 
    bit<16>                       key_nat_0_tcp_dstPort__mask;
}

@controlled extern flow_def_nat_0 query_nat_0(@matchKind("exact") in bit<1> nat_0_meta_is_ext_if, @matchKind("exact") in bool nat_0_ipv4__valid_, @matchKind("exact") in bool nat_0_tcp__valid_, @matchKind("ternary") in bit<32> nat_0_ipv4_srcAddr, @matchKind("ternary") in bit<32> nat_0_ipv4_dstAddr, @matchKind("ternary") in bit<16> nat_0_tcp_srcPort, @matchKind("ternary") in bit<16> nat_0_tcp_dstPort);
extern void end_nat_0();
enum flow_def_ipv4_lpm_0__action_type_t {
    set_nhop,
    _drop_7,
    NoAction_10
}

struct flow_def_ipv4_lpm_0 {
    bool                               hit;
    bool                               reach;
    flow_def_ipv4_lpm_0__action_type_t action_run;
    bit<32>                            set_nhop__nhop_ipv4;
    bit<9>                             set_nhop__port;
    @matchKind("lpm") 
    bit<32>                            key_ipv4_lpm_0_meta_ipv4_da__val;
    @matchKind("lpm") 
    bit<32>                            key_ipv4_lpm_0_meta_ipv4_da__prefix;
}

@controlled extern flow_def_ipv4_lpm_0 query_ipv4_lpm_0(@matchKind("lpm") in bit<32> ipv4_lpm_0_meta_ipv4_da);
extern void end_ipv4_lpm_0();
extern void key_match(in bool condition);
extern void angelic_assert(in bool condition);
extern void bug();

#include <core.p4>

#include <v1model.p4>

struct intrinsic_metadata_t {
    bit<4> mcast_grp;
    bit<4> egress_rid;
}

struct meta_t {
    bit<1>  do_forward;
    bit<32> ipv4_sa;
    bit<32> ipv4_da;
    bit<16> tcp_sp;
    bit<16> tcp_dp;
    bit<32> nhop_ipv4;
    bit<32> if_ipv4_addr;
    bit<48> if_mac_addr;
    bit<1>  is_ext_if;
    bit<16> tcpLength;
    bit<8>  if_index;
}

header cpu_header_t {
    bit<64> preamble;
    bit<8>  device;
    bit<8>  reason;
    bit<8>  if_index;
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
    bit<4>  res;
    bit<8>  flags;
    bit<16> window;
    bit<16> checksum;
    bit<16> urgentPtr;
}

struct metadata {
    bit<1>  _meta_do_forward0;
    bit<32> _meta_ipv4_sa1;
    bit<32> _meta_ipv4_da2;
    bit<16> _meta_tcp_sp3;
    bit<16> _meta_tcp_dp4;
    bit<32> _meta_nhop_ipv45;
    bit<32> _meta_if_ipv4_addr6;
    bit<48> _meta_if_mac_addr7;
    bit<1>  _meta_is_ext_if8;
    bit<16> _meta_tcpLength9;
    bit<8>  _meta_if_index10;
}

struct headers {
    @name(".cpu_header") 
    cpu_header_t cpu_header;
    @name(".ethernet") 
    ethernet_t   ethernet;
    @name(".ipv4") 
    ipv4_t       ipv4;
    @name(".tcp") 
    tcp_t        tcp;
}

parser ParserImpl(mutable_packet packet, out headers hdr, inout metadata meta, inout standard_metadata_t standard_metadata, inout error err) {
    bit<64> tmp_9;
    bit<64> tmp_10;
    bit<64> tmp_11;
    bit<64> tmp_12;
    @name(".parse_cpu_header") state parse_cpu_header {
        packet.extract<cpu_header_t>(hdr.cpu_header);
        transition select(hdr.cpu_header.isValid()) {
            true: parse_cpu_header_true;
            false: parse_cpu_header_false;
        }
    }
    state parse_cpu_header_true {
        meta._meta_if_index10 = hdr.cpu_header.if_index;
        transition parse_cpu_header_join;
    }
    state parse_cpu_header_false {
        bug();
        transition parse_cpu_header_join;
    }
    state parse_cpu_header_join {
        transition parse_ethernet;
    }
    @name(".parse_ethernet") state parse_ethernet {
        packet.extract<ethernet_t>(hdr.ethernet);
        transition select(hdr.ethernet.etherType) {
            16w0x800: parse_ipv4;
            default: accept;
        }
    }
    @name(".parse_ipv4") state parse_ipv4 {
        packet.extract<ipv4_t>(hdr.ipv4);
        transition select(hdr.ipv4.isValid()) {
            true: parse_ipv4_true;
            false: parse_ipv4_false;
        }
    }
    state parse_ipv4_true {
        meta._meta_ipv4_sa1 = hdr.ipv4.srcAddr;
        transition parse_ipv4_join;
    }
    state parse_ipv4_false {
        bug();
        transition parse_ipv4_join;
    }
    state parse_ipv4_join {
        transition select(hdr.ipv4.isValid()) {
            true: parse_ipv4_true_0;
            false: parse_ipv4_false_0;
        }
    }
    state parse_ipv4_true_0 {
        meta._meta_ipv4_da2 = hdr.ipv4.dstAddr;
        transition parse_ipv4_join_0;
    }
    state parse_ipv4_false_0 {
        bug();
        transition parse_ipv4_join_0;
    }
    state parse_ipv4_join_0 {
        transition select(hdr.ipv4.isValid()) {
            true: parse_ipv4_true_1;
            false: parse_ipv4_false_1;
        }
    }
    state parse_ipv4_true_1 {
        meta._meta_tcpLength9 = hdr.ipv4.totalLen + 16w65516;
        transition parse_ipv4_join_1;
    }
    state parse_ipv4_false_1 {
        bug();
        transition parse_ipv4_join_1;
    }
    state parse_ipv4_join_1 {
        transition select(hdr.ipv4.protocol) {
            8w0x6: parse_tcp;
            default: accept;
        }
    }
    @name(".parse_tcp") state parse_tcp {
        packet.extract<tcp_t>(hdr.tcp);
        transition select(hdr.tcp.isValid()) {
            true: parse_tcp_true;
            false: parse_tcp_false;
        }
    }
    state parse_tcp_true {
        meta._meta_tcp_sp3 = hdr.tcp.srcPort;
        transition parse_tcp_join;
    }
    state parse_tcp_false {
        bug();
        transition parse_tcp_join;
    }
    state parse_tcp_join {
        transition select(hdr.tcp.isValid()) {
            true: parse_tcp_true_0;
            false: parse_tcp_false_0;
        }
    }
    state parse_tcp_true_0 {
        meta._meta_tcp_dp4 = hdr.tcp.dstPort;
        transition parse_tcp_join_0;
    }
    state parse_tcp_false_0 {
        bug();
        transition parse_tcp_join_0;
    }
    state parse_tcp_join_0 {
        transition accept;
    }
    @name(".start") state start {
        meta._meta_if_index10 = (bit<8>)standard_metadata.ingress_port;
        tmp_12 = packet.lookahead<bit<64>>();
        tmp_11 = tmp_12;
        tmp_10 = tmp_11;
        tmp_9 = tmp_10;
        transition select(tmp_9[63:0]) {
            64w0: parse_cpu_header;
            default: parse_ethernet;
        }
    }
}

control egress(inout headers hdr, inout metadata meta, inout standard_metadata_t standard_metadata) {
    flow_def_send_frame_0 send_frame;
    flow_def_send_to_cpu_0 send_to_cpu;
    flow_def_send_frame_0 tmp_13;
    flow_def_send_to_cpu_0 tmp_14;
    apply {
        if (standard_metadata.instance_type == 32w0) {
            tmp_13 = query_send_frame_0(standard_metadata.egress_port);
            send_frame = tmp_13;
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
                    if (send_frame.action_run == flow_def_send_frame_0__action_type_t.do_rewrites) {
                        angelic_assert(true);
                        hdr.cpu_header.setInvalid();
                        if (hdr.ethernet.isValid()) {
                            hdr.ethernet.srcAddr = send_frame.do_rewrites__smac;
                        }
                        else {
                            bug();
                        }
                        if (hdr.ipv4.isValid()) {
                            hdr.ipv4.srcAddr = meta._meta_ipv4_sa1;
                        }
                        else {
                            bug();
                        }
                        if (hdr.ipv4.isValid()) {
                            hdr.ipv4.dstAddr = meta._meta_ipv4_da2;
                        }
                        else {
                            bug();
                        }
                        if (hdr.tcp.isValid()) {
                            hdr.tcp.srcPort = meta._meta_tcp_sp3;
                        }
                        else {
                            bug();
                        }
                        if (hdr.tcp.isValid()) {
                            hdr.tcp.dstPort = meta._meta_tcp_dp4;
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
        else {
            tmp_14 = query_send_to_cpu_0();
            send_to_cpu = tmp_14;
            if (send_to_cpu.action_run == flow_def_send_to_cpu_0__action_type_t.do_cpu_encap) {
                angelic_assert(true);
                hdr.cpu_header.setValid();
                if (hdr.cpu_header.isValid()) {
                    hdr.cpu_header.preamble = 64w0;
                }
                else {
                    bug();
                }
                if (hdr.cpu_header.isValid()) {
                    hdr.cpu_header.device = 8w0;
                }
                else {
                    bug();
                }
                if (hdr.cpu_header.isValid()) {
                    hdr.cpu_header.reason = 8w0xab;
                }
                else {
                    bug();
                }
                if (hdr.cpu_header.isValid()) {
                    hdr.cpu_header.if_index = meta._meta_if_index10;
                }
                else {
                    bug();
                }
            }
            else {
                ;
            }
            end_send_to_cpu_0();
        }
    }
}

control ingress(inout headers hdr, inout metadata meta, inout standard_metadata_t standard_metadata) {
    bool __track_egress_spec_0;
    flow_def_if_info_0 if_info;
    flow_def_nat_0 nat;
    flow_def_ipv4_lpm_0 ipv4_lpm;
    flow_def_forward_0 forward;
    flow_def_if_info_0 tmp_15;
    flow_def_nat_0 tmp_16;
    flow_def_ipv4_lpm_0 tmp_17;
    flow_def_forward_0 tmp_18;
    apply {
        __track_egress_spec_0 = false;
        tmp_15 = query_if_info_0(meta._meta_if_index10);
        if_info = tmp_15;
        if (if_info.hit) {
            key_match(meta._meta_if_index10 == if_info.key_if_info_0_meta_if_index);
        }
        if (if_info.action_run == flow_def_if_info_0__action_type_t.set_if_info) {
            angelic_assert(true);
            meta._meta_if_ipv4_addr6 = if_info.set_if_info__ipv4_addr;
            meta._meta_if_mac_addr7 = if_info.set_if_info__mac_addr;
            meta._meta_is_ext_if8 = if_info.set_if_info__is_ext;
        }
        else {
            if (if_info.action_run == flow_def_if_info_0__action_type_t._drop_6) {
                angelic_assert(true);
                standard_metadata.egress_spec = 9w511;
                __track_egress_spec_0 = true;
            }
            else {
                ;
            }
        }
        end_if_info_0();
        tmp_16 = query_nat_0(meta._meta_is_ext_if8, hdr.ipv4.isValid(), hdr.tcp.isValid(), hdr.ipv4.srcAddr, hdr.ipv4.dstAddr, hdr.tcp.srcPort, hdr.tcp.dstPort);
        nat = tmp_16;
        if (nat.hit) {
            key_match(meta._meta_is_ext_if8 == nat.key_nat_0_meta_is_ext_if && hdr.ipv4.isValid() == nat.key_nat_0_ipv4__valid_ && hdr.tcp.isValid() == nat.key_nat_0_tcp__valid_ && hdr.ipv4.srcAddr & nat.key_nat_0_ipv4_srcAddr__mask == nat.key_nat_0_ipv4_srcAddr__val & nat.key_nat_0_ipv4_srcAddr__mask && hdr.ipv4.dstAddr & nat.key_nat_0_ipv4_dstAddr__mask == nat.key_nat_0_ipv4_dstAddr__val & nat.key_nat_0_ipv4_dstAddr__mask && hdr.tcp.srcPort & nat.key_nat_0_tcp_srcPort__mask == nat.key_nat_0_tcp_srcPort__val & nat.key_nat_0_tcp_srcPort__mask && hdr.tcp.dstPort & nat.key_nat_0_tcp_dstPort__mask == nat.key_nat_0_tcp_dstPort__val & nat.key_nat_0_tcp_dstPort__mask);
            if (!(hdr.ipv4.isValid() || nat.key_nat_0_ipv4_srcAddr__mask == 32w0)) {
                bug();
            }
            if (!(hdr.ipv4.isValid() || nat.key_nat_0_ipv4_dstAddr__mask == 32w0)) {
                bug();
            }
            if (!(hdr.tcp.isValid() || nat.key_nat_0_tcp_srcPort__mask == 16w0)) {
                bug();
            }
            if (!(hdr.tcp.isValid() || nat.key_nat_0_tcp_dstPort__mask == 16w0)) {
                bug();
            }
        }
        if (nat.action_run == flow_def_nat_0__action_type_t.NoAction_11) {
            ;
        }
        else {
            if (nat.action_run == flow_def_nat_0__action_type_t.nat_no_nat) {
                angelic_assert(true);
                meta._meta_do_forward0 = 1w1;
            }
            else {
                if (nat.action_run == flow_def_nat_0__action_type_t.nat_hit_ext_to_int) {
                    angelic_assert(true);
                    meta._meta_do_forward0 = 1w1;
                    meta._meta_ipv4_da2 = nat.nat_hit_ext_to_int__dstAddr;
                    meta._meta_tcp_dp4 = nat.nat_hit_ext_to_int__dstPort;
                }
                else {
                    if (nat.action_run == flow_def_nat_0__action_type_t.nat_hit_int_to_ext) {
                        angelic_assert(true);
                        meta._meta_do_forward0 = 1w1;
                        meta._meta_ipv4_sa1 = nat.nat_hit_int_to_ext__srcAddr;
                        meta._meta_tcp_sp3 = nat.nat_hit_int_to_ext__srcPort;
                    }
                    else {
                        if (nat.action_run == flow_def_nat_0__action_type_t.nat_miss_ext_to_int) {
                            angelic_assert(true);
                            meta._meta_do_forward0 = 1w0;
                            standard_metadata.egress_spec = 9w511;
                            __track_egress_spec_0 = true;
                        }
                        else {
                            if (nat.action_run == flow_def_nat_0__action_type_t.nat_miss_int_to_ext) {
                                angelic_assert(true);
                                standard_metadata.clone_spec = 32w65786;
                            }
                            else {
                                if (nat.action_run == flow_def_nat_0__action_type_t._drop_8) {
                                    angelic_assert(true);
                                    standard_metadata.egress_spec = 9w511;
                                    __track_egress_spec_0 = true;
                                }
                                else {
                                    ;
                                }
                            }
                        }
                    }
                }
            }
        }
        end_nat_0();
        if (hdr.ipv4.isValid() || meta._meta_do_forward0 != 1w1) {
            if (meta._meta_do_forward0 == 1w1 && hdr.ipv4.ttl > 8w0) {
                tmp_17 = query_ipv4_lpm_0(meta._meta_ipv4_da2);
                ipv4_lpm = tmp_17;
                if (ipv4_lpm.hit) {
                    key_match(meta._meta_ipv4_da2 & (32w1 << ipv4_lpm.key_ipv4_lpm_0_meta_ipv4_da__prefix) + 32w4294967295 == ipv4_lpm.key_ipv4_lpm_0_meta_ipv4_da__val & (32w1 << ipv4_lpm.key_ipv4_lpm_0_meta_ipv4_da__prefix) + 32w4294967295);
                }
                if (ipv4_lpm.action_run == flow_def_ipv4_lpm_0__action_type_t.NoAction_10) {
                    ;
                }
                else {
                    if (ipv4_lpm.action_run == flow_def_ipv4_lpm_0__action_type_t._drop_7) {
                        angelic_assert(true);
                        standard_metadata.egress_spec = 9w511;
                        __track_egress_spec_0 = true;
                    }
                    else {
                        if (ipv4_lpm.action_run == flow_def_ipv4_lpm_0__action_type_t.set_nhop) {
                            angelic_assert(true);
                            meta._meta_nhop_ipv45 = ipv4_lpm.set_nhop__nhop_ipv4;
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
                tmp_18 = query_forward_0(meta._meta_nhop_ipv45);
                forward = tmp_18;
                if (forward.hit) {
                    key_match(meta._meta_nhop_ipv45 == forward.key_forward_0_meta_nhop_ipv4);
                }
                if (forward.action_run == flow_def_forward_0__action_type_t.NoAction_8) {
                    ;
                }
                else {
                    if (forward.action_run == flow_def_forward_0__action_type_t._drop_2) {
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
            }
        }
        else {
            bug();
        }
        if (!__track_egress_spec_0) {
            bug();
        }
    }
}

control DeparserImpl(mutable_packet packet, in headers hdr) {
    apply {
        packet.emit<cpu_header_t>(hdr.cpu_header);
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

struct tuple_1 {
    bit<32> field_10;
    bit<32> field_11;
    bit<8>  field_12;
    bit<8>  field_13;
    bit<16> field_14;
    bit<16> field_15;
    bit<16> field_16;
    bit<32> field_17;
    bit<32> field_18;
    bit<4>  field_19;
    bit<4>  field_20;
    bit<8>  field_21;
    bit<16> field_22;
    bit<16> field_23;
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
    if (discriminator == 16w1) {
        smto.checksum_error = smfrom.checksum_error;
        smto.clone_spec = smfrom.clone_spec;
        smto.deflect_on_drop = smfrom.deflect_on_drop;
        smto.deflection_flag = smfrom.deflection_flag;
        smto.deq_congest_stat = smfrom.deq_congest_stat;
        smto.deq_qdepth = smfrom.deq_qdepth;
        smto.deq_timedelta = smfrom.deq_timedelta;
        smto.drop = smfrom.drop;
        smto.egress_global_timestamp = smfrom.egress_global_timestamp;
        smto.egress_port = smfrom.egress_port;
        smto.egress_rid = smfrom.egress_rid;
        smto.egress_spec = smfrom.egress_spec;
        smto.enq_congest_stat = smfrom.enq_congest_stat;
        smto.enq_qdepth = smfrom.enq_qdepth;
        smto.enq_timestamp = smfrom.enq_timestamp;
        smto.ingress_cos = smfrom.ingress_cos;
        smto.ingress_global_timestamp = smfrom.ingress_global_timestamp;
        smto.ingress_port = smfrom.ingress_port;
        smto.instance_type = smfrom.instance_type;
        smto.lf_field_list = smfrom.lf_field_list;
        smto.mcast_grp = smfrom.mcast_grp;
        smto.mcast_hash = smfrom.mcast_hash;
        smto.packet_color = smfrom.packet_color;
        smto.packet_length = smfrom.packet_length;
        smto.parser_error = smfrom.parser_error;
        smto.priority = smfrom.priority;
        smto.qid = smfrom.qid;
        smto.recirculate_flag = smfrom.recirculate_flag;
        smto.recirculate_port = smfrom.recirculate_port;
        smto.resubmit_flag = smfrom.resubmit_flag;
    }
    else {
        ;
    }
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
            clone_metas_0._meta_do_forward0 = 1w0;
            clone_metas_0._meta_ipv4_sa1 = 32w0;
            clone_metas_0._meta_ipv4_da2 = 32w0;
            clone_metas_0._meta_tcp_sp3 = 16w0;
            clone_metas_0._meta_tcp_dp4 = 16w0;
            clone_metas_0._meta_nhop_ipv45 = 32w0;
            clone_metas_0._meta_if_ipv4_addr6 = 32w0;
            clone_metas_0._meta_if_mac_addr7 = 48w0;
            clone_metas_0._meta_is_ext_if8 = 1w0;
            clone_metas_0._meta_tcpLength9 = 16w0;
            clone_metas_0._meta_if_index10 = 8w0;
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
        hdrs.cpu_header.setInvalid();
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
        metas._meta_do_forward0 = 1w0;
        metas._meta_ipv4_sa1 = 32w0;
        metas._meta_ipv4_da2 = 32w0;
        metas._meta_tcp_sp3 = 16w0;
        metas._meta_tcp_dp4 = 16w0;
        metas._meta_nhop_ipv45 = 32w0;
        metas._meta_if_ipv4_addr6 = 32w0;
        metas._meta_if_mac_addr7 = 48w0;
        metas._meta_is_ext_if8 = 1w0;
        metas._meta_tcpLength9 = 16w0;
        metas._meta_if_index10 = 8w0;
    }
    standard_meta_0.instance_type = PKT_INSTANCE_TYPE_NORMAL_0;
    parse_and_run(pin, metas, standard_meta_0);
}
