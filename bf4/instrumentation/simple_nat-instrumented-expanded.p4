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

@controlled() extern flow_def_if_info_0 query_if_info_0(@matchKind("exact") in bit<8> if_info_0_meta_if_index);
extern void end_if_info_0();
enum flow_def_send_to_cpu_0__action_type_t {
    do_cpu_encap
}

struct flow_def_send_to_cpu_0 {
    bool                                  hit;
    bool                                  reach;
    flow_def_send_to_cpu_0__action_type_t action_run;
}

@controlled() extern flow_def_send_to_cpu_0 query_send_to_cpu_0();
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

@controlled() extern flow_def_forward_0 query_forward_0(@matchKind("exact") in bit<32> forward_0_meta_nhop_ipv4);
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

@controlled() extern flow_def_send_frame_0 query_send_frame_0(@matchKind("exact") in bit<9> send_frame_0_standard_metadata_egress_port);
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

@controlled() extern flow_def_nat_0 query_nat_0(@matchKind("exact") in bit<1> nat_0_meta_is_ext_if, @matchKind("exact") in bool nat_0_ipv4__valid_, @matchKind("exact") in bool nat_0_tcp__valid_, @matchKind("ternary") in bit<32> nat_0_ipv4_srcAddr, @matchKind("ternary") in bit<32> nat_0_ipv4_dstAddr, @matchKind("ternary") in bit<16> nat_0_tcp_srcPort, @matchKind("ternary") in bit<16> nat_0_tcp_dstPort);
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

@controlled() extern flow_def_ipv4_lpm_0 query_ipv4_lpm_0(@matchKind("lpm") in bit<32> ipv4_lpm_0_meta_ipv4_da);
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

parser ParserImpl(packet_in packet, out headers hdr, inout metadata meta, inout standard_metadata_t standard_metadata) {
    bit<64> tmp;
    bit<64> tmp_1;
    bit<64> tmp_2;
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
        tmp_2 = packet.lookahead<bit<64>>();
        tmp_1 = tmp_2;
        tmp = tmp_1;
        transition select(tmp[63:0]) {
            64w0: parse_cpu_header;
            default: parse_ethernet;
        }
    }
}

control egress(inout headers hdr, inout metadata meta, inout standard_metadata_t standard_metadata) {
    apply {
        if (standard_metadata.instance_type == 32w0) {
            flow_def_send_frame_0 send_frame;
            send_frame = query_send_frame_0(standard_metadata.egress_port);
            if (send_frame.hit) {
                key_match(standard_metadata.egress_port == send_frame.key_send_frame_0_standard_metadata_egress_port);
            }
            if (send_frame.action_run == flow_def_send_frame_0__action_type_t.NoAction_0) {
            }
            else  {
                if (send_frame.action_run == flow_def_send_frame_0__action_type_t._drop) {
                    angelic_assert(true);
                    {
                        standard_metadata.egress_spec = 9w511;
                    }
                }
                else  {
                    if (send_frame.action_run == flow_def_send_frame_0__action_type_t.do_rewrites) {
                        angelic_assert(true);
                        {
                            hdr.cpu_header.setInvalid();
                            if (hdr.ethernet.isValid())  {
                                hdr.ethernet.srcAddr = send_frame.do_rewrites__smac;
                            } 
                            else  {
                                bug();
                            }
                            if (hdr.ipv4.isValid())  {
                                hdr.ipv4.srcAddr = meta._meta_ipv4_sa1;
                            } 
                            else  {
                                bug();
                            }
                            if (hdr.ipv4.isValid())  {
                                hdr.ipv4.dstAddr = meta._meta_ipv4_da2;
                            } 
                            else  {
                                bug();
                            }
                            if (hdr.tcp.isValid())  {
                                hdr.tcp.srcPort = meta._meta_tcp_sp3;
                            } 
                            else  {
                                bug();
                            }
                            if (hdr.tcp.isValid())  {
                                hdr.tcp.dstPort = meta._meta_tcp_dp4;
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
            end_send_frame_0();
        }
        else {
            flow_def_send_to_cpu_0 send_to_cpu;
            send_to_cpu = query_send_to_cpu_0();
            ;
            if (send_to_cpu.action_run == flow_def_send_to_cpu_0__action_type_t.do_cpu_encap) {
                angelic_assert(true);
                {
                    hdr.cpu_header.setValid();
                    if (hdr.cpu_header.isValid())  {
                        hdr.cpu_header.preamble = 64w0;
                    } 
                    else  {
                        bug();
                    }
                    if (hdr.cpu_header.isValid())  {
                        hdr.cpu_header.device = 8w0;
                    } 
                    else  {
                        bug();
                    }
                    if (hdr.cpu_header.isValid())  {
                        hdr.cpu_header.reason = 8w0xab;
                    } 
                    else  {
                        bug();
                    }
                    if (hdr.cpu_header.isValid())  {
                        hdr.cpu_header.if_index = meta._meta_if_index10;
                    } 
                    else  {
                        bug();
                    }
                }
            }
            else  {
                ;
            }
            end_send_to_cpu_0();
        }
    }
}

control ingress(inout headers hdr, inout metadata meta, inout standard_metadata_t standard_metadata) {
    bool __track_egress_spec_0;
    apply {
        __track_egress_spec_0 = false;
        {
            flow_def_if_info_0 if_info;
            if_info = query_if_info_0(meta._meta_if_index10);
            if (if_info.hit) {
                key_match(meta._meta_if_index10 == if_info.key_if_info_0_meta_if_index);
            }
            if (if_info.action_run == flow_def_if_info_0__action_type_t.set_if_info) {
                angelic_assert(true);
                {
                    meta._meta_if_ipv4_addr6 = if_info.set_if_info__ipv4_addr;
                    meta._meta_if_mac_addr7 = if_info.set_if_info__mac_addr;
                    meta._meta_is_ext_if8 = if_info.set_if_info__is_ext;
                }
            }
            else  {
                if (if_info.action_run == flow_def_if_info_0__action_type_t._drop_6) {
                    angelic_assert(true);
                    {
                        standard_metadata.egress_spec = 9w511;
                        __track_egress_spec_0 = true;
                    }
                }
                else  {
                    ;
                }
            }
            end_if_info_0();
        }
        {
            flow_def_nat_0 nat;
            nat = query_nat_0(meta._meta_is_ext_if8, hdr.ipv4.isValid(), hdr.tcp.isValid(), hdr.ipv4.srcAddr, hdr.ipv4.dstAddr, hdr.tcp.srcPort, hdr.tcp.dstPort);
            if (nat.hit) {
                key_match(meta._meta_is_ext_if8 == nat.key_nat_0_meta_is_ext_if && hdr.ipv4.isValid() == nat.key_nat_0_ipv4__valid_ && hdr.tcp.isValid() == nat.key_nat_0_tcp__valid_ && hdr.ipv4.srcAddr & nat.key_nat_0_ipv4_srcAddr__mask == nat.key_nat_0_ipv4_srcAddr__val & nat.key_nat_0_ipv4_srcAddr__mask && hdr.ipv4.dstAddr & nat.key_nat_0_ipv4_dstAddr__mask == nat.key_nat_0_ipv4_dstAddr__val & nat.key_nat_0_ipv4_dstAddr__mask && hdr.tcp.srcPort & nat.key_nat_0_tcp_srcPort__mask == nat.key_nat_0_tcp_srcPort__val & nat.key_nat_0_tcp_srcPort__mask && hdr.tcp.dstPort & nat.key_nat_0_tcp_dstPort__mask == nat.key_nat_0_tcp_dstPort__val & nat.key_nat_0_tcp_dstPort__mask);
                if (!(hdr.ipv4.isValid() || nat.key_nat_0_ipv4_srcAddr__mask == 32w0))  {
                    bug();
                } 
                if (!(hdr.ipv4.isValid() || nat.key_nat_0_ipv4_dstAddr__mask == 32w0))  {
                    bug();
                } 
                if (!(hdr.tcp.isValid() || nat.key_nat_0_tcp_srcPort__mask == 16w0))  {
                    bug();
                } 
                if (!(hdr.tcp.isValid() || nat.key_nat_0_tcp_dstPort__mask == 16w0))  {
                    bug();
                } 
            }
            if (nat.action_run == flow_def_nat_0__action_type_t.NoAction_11) {
            }
            else  {
                if (nat.action_run == flow_def_nat_0__action_type_t.nat_no_nat) {
                    angelic_assert(true);
                    {
                        meta._meta_do_forward0 = 1w1;
                    }
                }
                else  {
                    if (nat.action_run == flow_def_nat_0__action_type_t.nat_hit_ext_to_int) {
                        angelic_assert(true);
                        {
                            meta._meta_do_forward0 = 1w1;
                            meta._meta_ipv4_da2 = nat.nat_hit_ext_to_int__dstAddr;
                            meta._meta_tcp_dp4 = nat.nat_hit_ext_to_int__dstPort;
                        }
                    }
                    else  {
                        if (nat.action_run == flow_def_nat_0__action_type_t.nat_hit_int_to_ext) {
                            angelic_assert(true);
                            {
                                meta._meta_do_forward0 = 1w1;
                                meta._meta_ipv4_sa1 = nat.nat_hit_int_to_ext__srcAddr;
                                meta._meta_tcp_sp3 = nat.nat_hit_int_to_ext__srcPort;
                            }
                        }
                        else  {
                            if (nat.action_run == flow_def_nat_0__action_type_t.nat_miss_ext_to_int) {
                                angelic_assert(true);
                                {
                                    meta._meta_do_forward0 = 1w0;
                                    standard_metadata.egress_spec = 9w511;
                                    __track_egress_spec_0 = true;
                                }
                            }
                            else  {
                                if (nat.action_run == flow_def_nat_0__action_type_t.nat_miss_int_to_ext) {
                                    angelic_assert(true);
                                    {
                                        standard_metadata.clone_spec = 32w65786;
                                    }
                                }
                                else  {
                                    if (nat.action_run == flow_def_nat_0__action_type_t._drop_8) {
                                        angelic_assert(true);
                                        {
                                            standard_metadata.egress_spec = 9w511;
                                            __track_egress_spec_0 = true;
                                        }
                                    }
                                    else  {
                                        ;
                                    }
                                }
                            }
                        }
                    }
                }
            }
            end_nat_0();
        }
        if (hdr.ipv4.isValid() || meta._meta_do_forward0 != 1w1)  {
            if (meta._meta_do_forward0 == 1w1 && hdr.ipv4.ttl > 8w0) {
                {
                    flow_def_ipv4_lpm_0 ipv4_lpm;
                    ipv4_lpm = query_ipv4_lpm_0(meta._meta_ipv4_da2);
                    if (ipv4_lpm.hit) {
                        key_match(meta._meta_ipv4_da2 & (32w1 << ipv4_lpm.key_ipv4_lpm_0_meta_ipv4_da__prefix) - 32w1 == ipv4_lpm.key_ipv4_lpm_0_meta_ipv4_da__val & (32w1 << ipv4_lpm.key_ipv4_lpm_0_meta_ipv4_da__prefix) - 32w1);
                    }
                    if (ipv4_lpm.action_run == flow_def_ipv4_lpm_0__action_type_t.NoAction_10) {
                    }
                    else  {
                        if (ipv4_lpm.action_run == flow_def_ipv4_lpm_0__action_type_t._drop_7) {
                            angelic_assert(true);
                            {
                                standard_metadata.egress_spec = 9w511;
                                __track_egress_spec_0 = true;
                            }
                        }
                        else  {
                            if (ipv4_lpm.action_run == flow_def_ipv4_lpm_0__action_type_t.set_nhop) {
                                angelic_assert(true);
                                {
                                    meta._meta_nhop_ipv45 = ipv4_lpm.set_nhop__nhop_ipv4;
                                    standard_metadata.egress_spec = ipv4_lpm.set_nhop__port;
                                    __track_egress_spec_0 = true;
                                    if (hdr.ipv4.isValid() && hdr.ipv4.isValid())  {
                                        hdr.ipv4.ttl = hdr.ipv4.ttl + 8w255;
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
                    end_ipv4_lpm_0();
                }
                {
                    flow_def_forward_0 forward;
                    forward = query_forward_0(meta._meta_nhop_ipv45);
                    if (forward.hit) {
                        key_match(meta._meta_nhop_ipv45 == forward.key_forward_0_meta_nhop_ipv4);
                    }
                    if (forward.action_run == flow_def_forward_0__action_type_t.NoAction_8) {
                    }
                    else  {
                        if (forward.action_run == flow_def_forward_0__action_type_t._drop_2) {
                            angelic_assert(true);
                            {
                                standard_metadata.egress_spec = 9w511;
                                __track_egress_spec_0 = true;
                            }
                        }
                        else  {
                            if (forward.action_run == flow_def_forward_0__action_type_t.set_dmac) {
                                angelic_assert(true);
                                {
                                    if (hdr.ethernet.isValid())  {
                                        hdr.ethernet.dstAddr = forward.set_dmac__dmac;
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
                    end_forward_0();
                }
            }
        } 
        else  {
            bug();
        }
        if (!__track_egress_spec_0)  {
            bug();
        } 
    }
}

control DeparserImpl(packet_out packet, in headers hdr) {
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
    else  {
        ;
    }
}
