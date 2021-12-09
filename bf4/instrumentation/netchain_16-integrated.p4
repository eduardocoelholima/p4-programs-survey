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
enum flow_def_drop_packet_0__action_type_t {
    drop_packet_act
}

struct flow_def_drop_packet_0 {
    bool                                  hit;
    bool                                  reach;
    flow_def_drop_packet_0__action_type_t action_run;
}

@controlled extern flow_def_drop_packet_0 query_drop_packet_0();
extern void end_drop_packet_0();
enum flow_def_assign_value_0__action_type_t {
    assign_value_act
}

struct flow_def_assign_value_0 {
    bool                                   hit;
    bool                                   reach;
    flow_def_assign_value_0__action_type_t action_run;
}

@controlled extern flow_def_assign_value_0 query_assign_value_0();
extern void end_assign_value_0();
enum flow_def_ethernet_set_mac_0__action_type_t {
    ethernet_set_mac_act
}

struct flow_def_ethernet_set_mac_0 {
    bool                                       hit;
    bool                                       reach;
    flow_def_ethernet_set_mac_0__action_type_t action_run;
    bit<48>                                    ethernet_set_mac_act__smac;
    bit<48>                                    ethernet_set_mac_act__dmac;
    @matchKind("exact") 
    bit<9>                                     key_ethernet_set_mac_0_standard_metadata_egress_port;
}

@controlled extern flow_def_ethernet_set_mac_0 query_ethernet_set_mac_0(@matchKind("exact") in bit<9> ethernet_set_mac_0_standard_metadata_egress_port);
extern void end_ethernet_set_mac_0();
enum flow_def_get_my_address_0__action_type_t {
    get_my_address_act
}

struct flow_def_get_my_address_0 {
    bool                                     hit;
    bool                                     reach;
    flow_def_get_my_address_0__action_type_t action_run;
    bit<32>                                  get_my_address_act__sw_ip;
    bit<16>                                  get_my_address_act__sw_role;
    @matchKind("exact") 
    bit<128>                                 key_get_my_address_0_nc_hdr_key;
}

@controlled extern flow_def_get_my_address_0 query_get_my_address_0(@matchKind("exact") in bit<128> get_my_address_0_nc_hdr_key);
extern void end_get_my_address_0();
enum flow_def_gen_reply_0__action_type_t {
    gen_reply_act
}

struct flow_def_gen_reply_0 {
    bool                                hit;
    bool                                reach;
    flow_def_gen_reply_0__action_type_t action_run;
    bit<8>                              gen_reply_act__message_type;
    @matchKind("exact") 
    bit<8>                              key_gen_reply_0_nc_hdr_op;
}

@controlled extern flow_def_gen_reply_0 query_gen_reply_0(@matchKind("exact") in bit<8> gen_reply_0_nc_hdr_op);
extern void end_gen_reply_0();
enum flow_def_find_index_0__action_type_t {
    find_index_act
}

struct flow_def_find_index_0 {
    bool                                 hit;
    bool                                 reach;
    flow_def_find_index_0__action_type_t action_run;
    bit<16>                              find_index_act__index;
    @matchKind("exact") 
    bit<128>                             key_find_index_0_nc_hdr_key;
}

@controlled extern flow_def_find_index_0 query_find_index_0(@matchKind("exact") in bit<128> find_index_0_nc_hdr_key);
extern void end_find_index_0();
enum flow_def_failure_recovery_0__action_type_t {
    failover_act,
    failover_write_reply_act,
    failure_recovery_act,
    nop,
    drop_packet_act_2,
    NoAction_17
}

struct flow_def_failure_recovery_0 {
    bool                                       hit;
    bool                                       reach;
    flow_def_failure_recovery_0__action_type_t action_run;
    bit<32>                                    failure_recovery_act__nexthop;
    @matchKind("ternary") 
    bit<32>                                    key_failure_recovery_0_ipv4_dstAddr__val;
    @matchKind("ternary") 
    bit<32>                                    key_failure_recovery_0_ipv4_dstAddr__mask;
    @matchKind("ternary") 
    bit<32>                                    key_failure_recovery_0_overlay_1__swip__val;
    @matchKind("ternary") 
    bit<32>                                    key_failure_recovery_0_overlay_1__swip__mask;
    @matchKind("ternary") 
    bit<16>                                    key_failure_recovery_0_nc_hdr_vgroup__val;
    @matchKind("ternary") 
    bit<16>                                    key_failure_recovery_0_nc_hdr_vgroup__mask;
}

@controlled extern flow_def_failure_recovery_0 query_failure_recovery_0(@matchKind("ternary") in bit<32> failure_recovery_0_ipv4_dstAddr, @matchKind("ternary") in bit<32> failure_recovery_0_overlay_1__swip, @matchKind("ternary") in bit<16> failure_recovery_0_nc_hdr_vgroup);
extern void end_failure_recovery_0();
enum flow_def_ipv4_route_0__action_type_t {
    set_egress,
    NoAction_23
}

struct flow_def_ipv4_route_0 {
    bool                                 hit;
    bool                                 reach;
    flow_def_ipv4_route_0__action_type_t action_run;
    bit<9>                               set_egress__egress_spec;
    @matchKind("exact") 
    bit<32>                              key_ipv4_route_0_ipv4_dstAddr;
}

@controlled extern flow_def_ipv4_route_0 query_ipv4_route_0(@matchKind("exact") in bit<32> ipv4_route_0_ipv4_dstAddr);
extern void end_ipv4_route_0();
enum flow_def_read_value_0__action_type_t {
    read_value_act
}

struct flow_def_read_value_0 {
    bool                                 hit;
    bool                                 reach;
    flow_def_read_value_0__action_type_t action_run;
}

@controlled extern flow_def_read_value_0 query_read_value_0();
extern void end_read_value_0();
enum flow_def_pop_chain_again_0__action_type_t {
    pop_chain_act_2
}

struct flow_def_pop_chain_again_0 {
    bool                                      hit;
    bool                                      reach;
    flow_def_pop_chain_again_0__action_type_t action_run;
}

@controlled extern flow_def_pop_chain_again_0 query_pop_chain_again_0();
extern void end_pop_chain_again_0();
enum flow_def_pop_chain_0__action_type_t {
    pop_chain_act
}

struct flow_def_pop_chain_0 {
    bool                                hit;
    bool                                reach;
    flow_def_pop_chain_0__action_type_t action_run;
}

@controlled extern flow_def_pop_chain_0 query_pop_chain_0();
extern void end_pop_chain_0();
enum flow_def_maintain_sequence_0__action_type_t {
    maintain_sequence_act
}

struct flow_def_maintain_sequence_0 {
    bool                                        hit;
    bool                                        reach;
    flow_def_maintain_sequence_0__action_type_t action_run;
}

@controlled extern flow_def_maintain_sequence_0 query_maintain_sequence_0();
extern void end_maintain_sequence_0();
enum flow_def_get_sequence_0__action_type_t {
    get_sequence_act
}

struct flow_def_get_sequence_0 {
    bool                                   hit;
    bool                                   reach;
    flow_def_get_sequence_0__action_type_t action_run;
}

@controlled extern flow_def_get_sequence_0 query_get_sequence_0();
extern void end_get_sequence_0();
enum flow_def_get_next_hop_0__action_type_t {
    get_next_hop_act
}

struct flow_def_get_next_hop_0 {
    bool                                   hit;
    bool                                   reach;
    flow_def_get_next_hop_0__action_type_t action_run;
}

@controlled extern flow_def_get_next_hop_0 query_get_next_hop_0();
extern void end_get_next_hop_0();
extern void key_match(in bool condition);
extern void angelic_assert(in bool condition);
extern void bug();

#include <core.p4>

#include <v1model.p4>

struct location_t {
    bit<16> index;
}

struct my_md_t {
    bit<32> ipaddress;
    bit<16> role;
    bit<16> failed;
}

struct reply_addr_t {
    bit<32> ipv4_srcAddr;
    bit<32> ipv4_dstAddr;
}

struct sequence_md_t {
    bit<16> seq;
    bit<16> tmp;
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

header nc_hdr_t {
    bit<8>   op;
    bit<8>   sc;
    bit<16>  seq;
    bit<128> key;
    bit<128> value;
    bit<16>  vgroup;
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

header udp_t {
    bit<16> srcPort;
    bit<16> dstPort;
    bit<16> len;
    bit<16> checksum;
}

header overlay_t {
    bit<32> swip;
}

struct metadata {
    bit<16> _location_index0;
    bit<32> _my_md_ipaddress1;
    bit<16> _my_md_role2;
    bit<16> _my_md_failed3;
    bit<32> _reply_to_client_md_ipv4_srcAddr4;
    bit<32> _reply_to_client_md_ipv4_dstAddr5;
    bit<16> _sequence_md_seq6;
    bit<16> _sequence_md_tmp7;
}

@array struct overlay_t_10 {
    bit<16>       nxt;
    @raw 
    overlay_t[10] elements;
}

struct headers {
    @name(".ethernet") 
    ethernet_t   ethernet;
    @name(".ipv4") 
    ipv4_t       ipv4;
    @name(".nc_hdr") 
    nc_hdr_t     nc_hdr;
    @name(".tcp") 
    tcp_t        tcp;
    @name(".udp") 
    udp_t        udp;
    @name(".overlay") 
    overlay_t_10 overlay;
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
            8w17: parse_udp;
            default: accept;
        }
    }
    @name(".parse_nc_hdr") state parse_nc_hdr {
        packet.extract<nc_hdr_t>(hdr.nc_hdr);
        transition select(hdr.nc_hdr.op) {
            8w10: accept;
            8w12: accept;
            default: accept;
        }
    }
    state parse_overlay {
        transition select(hdr.overlay.nxt < 16w10) {
            true: parse_overlay_0;
            default: reject;
        }
    }
    @name(".parse_tcp") state parse_tcp {
        packet.extract<tcp_t>(hdr.tcp);
        transition accept;
    }
    @name(".parse_udp") state parse_udp {
        packet.extract<udp_t>(hdr.udp);
        transition select(hdr.udp.dstPort) {
            16w8888: parse_overlay;
            16w8889: parse_overlay;
            default: accept;
        }
    }
    @name(".start") state start {
        hdr.overlay.nxt = 16w0;
        transition parse_ethernet;
    }
    state parse_overlay_0 {
        packet.extract<overlay_t>(hdr.overlay.elements[hdr.overlay.nxt]);
        hdr.overlay.nxt = hdr.overlay.nxt + 16w1;
        transition select(hdr.overlay.elements[hdr.overlay.nxt + 16w65535].swip) {
            32w0: parse_nc_hdr;
            default: parse_overlay;
        }
    }
}

control egress(inout headers hdr, inout metadata meta, inout standard_metadata_t standard_metadata) {
    flow_def_ethernet_set_mac_0 ethernet_set_mac;
    flow_def_ethernet_set_mac_0 tmp_14;
    apply {
        tmp_14 = query_ethernet_set_mac_0(standard_metadata.egress_port);
        ethernet_set_mac = tmp_14;
        if (ethernet_set_mac.hit) {
            key_match(standard_metadata.egress_port == ethernet_set_mac.key_ethernet_set_mac_0_standard_metadata_egress_port);
        }
        if (ethernet_set_mac.action_run == flow_def_ethernet_set_mac_0__action_type_t.ethernet_set_mac_act) {
            angelic_assert(true);
            if (hdr.ethernet.isValid()) {
                hdr.ethernet.srcAddr = ethernet_set_mac.ethernet_set_mac_act__smac;
            }
            else {
                bug();
            }
            if (hdr.ethernet.isValid()) {
                hdr.ethernet.dstAddr = ethernet_set_mac.ethernet_set_mac_act__dmac;
            }
            else {
                bug();
            }
        }
        else {
            ;
        }
        end_ethernet_set_mac_0();
    }
}

control ingress(inout headers hdr, inout metadata meta, inout standard_metadata_t standard_metadata) {
    bool __track_egress_spec_0;
    flow_def_get_my_address_0 get_my_address;
    flow_def_find_index_0 find_index;
    flow_def_get_sequence_0 get_sequence;
    flow_def_read_value_0 read_value;
    flow_def_maintain_sequence_0 maintain_sequence;
    flow_def_assign_value_0 assign_value;
    flow_def_pop_chain_0 pop_chain;
    flow_def_drop_packet_0 drop_packet;
    flow_def_pop_chain_again_0 pop_chain_again;
    flow_def_gen_reply_0 gen_reply;
    flow_def_get_next_hop_0 get_next_hop;
    flow_def_failure_recovery_0 failure_recovery;
    flow_def_ipv4_route_0 ipv4_route;
    flow_def_get_my_address_0 tmp_15;
    flow_def_find_index_0 tmp_16;
    flow_def_get_sequence_0 tmp_17;
    flow_def_read_value_0 tmp_18;
    flow_def_maintain_sequence_0 tmp_19;
    flow_def_assign_value_0 tmp_20;
    flow_def_pop_chain_0 tmp_21;
    flow_def_drop_packet_0 tmp_22;
    flow_def_pop_chain_again_0 tmp_23;
    flow_def_gen_reply_0 tmp_24;
    flow_def_get_next_hop_0 tmp_25;
    flow_def_failure_recovery_0 tmp_26;
    flow_def_ipv4_route_0 tmp_27;
    @name(".sequence_reg") register<bit<16>>(32w4096) sequence_reg_0;
    @name(".value_reg") register<bit<128>>(32w4096) value_reg_0;
    apply {
        __track_egress_spec_0 = false;
        if (hdr.nc_hdr.isValid()) {
            tmp_15 = query_get_my_address_0(hdr.nc_hdr.key);
            get_my_address = tmp_15;
            if (get_my_address.hit) {
                key_match(hdr.nc_hdr.key == get_my_address.key_get_my_address_0_nc_hdr_key);
                if (!hdr.nc_hdr.isValid()) {
                    bug();
                }
            }
            if (get_my_address.action_run == flow_def_get_my_address_0__action_type_t.get_my_address_act) {
                angelic_assert(true);
                meta._my_md_ipaddress1 = get_my_address.get_my_address_act__sw_ip;
                meta._my_md_role2 = get_my_address.get_my_address_act__sw_role;
            }
            else {
                ;
            }
            end_get_my_address_0();
            if (hdr.ipv4.isValid()) {
                if (hdr.ipv4.dstAddr == meta._my_md_ipaddress1) {
                    tmp_16 = query_find_index_0(hdr.nc_hdr.key);
                    find_index = tmp_16;
                    if (find_index.hit) {
                        key_match(hdr.nc_hdr.key == find_index.key_find_index_0_nc_hdr_key);
                        if (!hdr.nc_hdr.isValid()) {
                            bug();
                        }
                    }
                    if (find_index.action_run == flow_def_find_index_0__action_type_t.find_index_act) {
                        angelic_assert(true);
                        meta._location_index0 = find_index.find_index_act__index;
                    }
                    else {
                        ;
                    }
                    end_find_index_0();
                    tmp_17 = query_get_sequence_0();
                    get_sequence = tmp_17;
                    if (get_sequence.action_run == flow_def_get_sequence_0__action_type_t.get_sequence_act) {
                        angelic_assert(true);
                        if ((bit<32>)meta._location_index0 >= 32w4096) {
                            bug();
                        }
                        sequence_reg_0.read(meta._sequence_md_seq6, (bit<32>)meta._location_index0);
                    }
                    else {
                        ;
                    }
                    end_get_sequence_0();
                    if (hdr.nc_hdr.isValid()) {
                        if (hdr.nc_hdr.op == 8w10) {
                            tmp_18 = query_read_value_0();
                            read_value = tmp_18;
                            if (read_value.action_run == flow_def_read_value_0__action_type_t.read_value_act) {
                                angelic_assert(true);
                                if ((bit<32>)meta._location_index0 >= 32w4096) {
                                    bug();
                                }
                                value_reg_0.read(hdr.nc_hdr.value, (bit<32>)meta._location_index0);
                            }
                            else {
                                ;
                            }
                            end_read_value_0();
                        }
                        else {
                            if (hdr.nc_hdr.isValid()) {
                                if (hdr.nc_hdr.op == 8w12) {
                                    if (meta._my_md_role2 == 16w100) {
                                        tmp_19 = query_maintain_sequence_0();
                                        maintain_sequence = tmp_19;
                                        if (maintain_sequence.action_run == flow_def_maintain_sequence_0__action_type_t.maintain_sequence_act) {
                                            angelic_assert(true);
                                            meta._sequence_md_seq6 = meta._sequence_md_seq6 + 16w1;
                                            if ((bit<32>)meta._location_index0 >= 32w4096) {
                                                bug();
                                            }
                                            sequence_reg_0.write((bit<32>)meta._location_index0, meta._sequence_md_seq6);
                                            if ((bit<32>)meta._location_index0 >= 32w4096) {
                                                bug();
                                            }
                                            sequence_reg_0.read(hdr.nc_hdr.seq, (bit<32>)meta._location_index0);
                                        }
                                        else {
                                            ;
                                        }
                                        end_maintain_sequence_0();
                                    }
                                    if (hdr.nc_hdr.isValid() || meta._my_md_role2 == 16w100) {
                                        if (meta._my_md_role2 == 16w100 || hdr.nc_hdr.seq > meta._sequence_md_seq6) {
                                            tmp_20 = query_assign_value_0();
                                            assign_value = tmp_20;
                                            if (assign_value.action_run == flow_def_assign_value_0__action_type_t.assign_value_act) {
                                                angelic_assert(true);
                                                if (hdr.nc_hdr.isValid()) {
                                                    if ((bit<32>)meta._location_index0 >= 32w4096) {
                                                        bug();
                                                    }
                                                    sequence_reg_0.write((bit<32>)meta._location_index0, hdr.nc_hdr.seq);
                                                }
                                                else {
                                                    bug();
                                                }
                                                if (hdr.nc_hdr.isValid()) {
                                                    if ((bit<32>)meta._location_index0 >= 32w4096) {
                                                        bug();
                                                    }
                                                    value_reg_0.write((bit<32>)meta._location_index0, hdr.nc_hdr.value);
                                                }
                                                else {
                                                    bug();
                                                }
                                            }
                                            else {
                                                ;
                                            }
                                            end_assign_value_0();
                                            tmp_21 = query_pop_chain_0();
                                            pop_chain = tmp_21;
                                            if (pop_chain.action_run == flow_def_pop_chain_0__action_type_t.pop_chain_act) {
                                                angelic_assert(true);
                                                if (hdr.nc_hdr.isValid() && hdr.nc_hdr.isValid()) {
                                                    hdr.nc_hdr.sc = hdr.nc_hdr.sc + 8w255;
                                                }
                                                else {
                                                    bug();
                                                }
                                                hdr.overlay.elements[0] = hdr.overlay.elements[1];
                                                hdr.overlay.elements[1] = hdr.overlay.elements[2];
                                                hdr.overlay.elements[2] = hdr.overlay.elements[3];
                                                hdr.overlay.elements[3] = hdr.overlay.elements[4];
                                                hdr.overlay.elements[4] = hdr.overlay.elements[5];
                                                hdr.overlay.elements[5] = hdr.overlay.elements[6];
                                                hdr.overlay.elements[6] = hdr.overlay.elements[7];
                                                hdr.overlay.elements[7] = hdr.overlay.elements[8];
                                                hdr.overlay.elements[8] = hdr.overlay.elements[9];
                                                hdr.overlay.elements[9].setInvalid();
                                                if (hdr.overlay.nxt < 16w1) {
                                                    hdr.overlay.nxt = 16w0;
                                                }
                                                else {
                                                    hdr.overlay.nxt = hdr.overlay.nxt + 16w65535;
                                                }
                                                if (hdr.udp.isValid() && hdr.udp.isValid()) {
                                                    hdr.udp.len = hdr.udp.len + 16w65532;
                                                }
                                                else {
                                                    bug();
                                                }
                                                if (hdr.ipv4.isValid() && hdr.ipv4.isValid()) {
                                                    hdr.ipv4.totalLen = hdr.ipv4.totalLen + 16w65532;
                                                }
                                                else {
                                                    bug();
                                                }
                                            }
                                            else {
                                                ;
                                            }
                                            end_pop_chain_0();
                                        }
                                        else {
                                            tmp_22 = query_drop_packet_0();
                                            drop_packet = tmp_22;
                                            if (drop_packet.action_run == flow_def_drop_packet_0__action_type_t.drop_packet_act) {
                                                angelic_assert(true);
                                                standard_metadata.egress_spec = 9w511;
                                                __track_egress_spec_0 = true;
                                            }
                                            else {
                                                ;
                                            }
                                            end_drop_packet_0();
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
                    else {
                        bug();
                    }
                    if (meta._my_md_role2 == 16w102) {
                        tmp_23 = query_pop_chain_again_0();
                        pop_chain_again = tmp_23;
                        if (pop_chain_again.action_run == flow_def_pop_chain_again_0__action_type_t.pop_chain_act_2) {
                            angelic_assert(true);
                            if (hdr.nc_hdr.isValid() && hdr.nc_hdr.isValid()) {
                                hdr.nc_hdr.sc = hdr.nc_hdr.sc + 8w255;
                            }
                            else {
                                bug();
                            }
                            hdr.overlay.elements[0] = hdr.overlay.elements[1];
                            hdr.overlay.elements[1] = hdr.overlay.elements[2];
                            hdr.overlay.elements[2] = hdr.overlay.elements[3];
                            hdr.overlay.elements[3] = hdr.overlay.elements[4];
                            hdr.overlay.elements[4] = hdr.overlay.elements[5];
                            hdr.overlay.elements[5] = hdr.overlay.elements[6];
                            hdr.overlay.elements[6] = hdr.overlay.elements[7];
                            hdr.overlay.elements[7] = hdr.overlay.elements[8];
                            hdr.overlay.elements[8] = hdr.overlay.elements[9];
                            hdr.overlay.elements[9].setInvalid();
                            if (hdr.overlay.nxt < 16w1) {
                                hdr.overlay.nxt = 16w0;
                            }
                            else {
                                hdr.overlay.nxt = hdr.overlay.nxt + 16w65535;
                            }
                            if (hdr.udp.isValid() && hdr.udp.isValid()) {
                                hdr.udp.len = hdr.udp.len + 16w65532;
                            }
                            else {
                                bug();
                            }
                            if (hdr.ipv4.isValid() && hdr.ipv4.isValid()) {
                                hdr.ipv4.totalLen = hdr.ipv4.totalLen + 16w65532;
                            }
                            else {
                                bug();
                            }
                        }
                        else {
                            ;
                        }
                        end_pop_chain_again_0();
                        tmp_24 = query_gen_reply_0(hdr.nc_hdr.op);
                        gen_reply = tmp_24;
                        if (gen_reply.hit) {
                            key_match(hdr.nc_hdr.op == gen_reply.key_gen_reply_0_nc_hdr_op);
                            if (!hdr.nc_hdr.isValid()) {
                                bug();
                            }
                        }
                        if (gen_reply.action_run == flow_def_gen_reply_0__action_type_t.gen_reply_act) {
                            angelic_assert(true);
                            if (hdr.ipv4.isValid()) {
                                meta._reply_to_client_md_ipv4_srcAddr4 = hdr.ipv4.dstAddr;
                            }
                            else {
                                bug();
                            }
                            if (hdr.ipv4.isValid()) {
                                meta._reply_to_client_md_ipv4_dstAddr5 = hdr.ipv4.srcAddr;
                            }
                            else {
                                bug();
                            }
                            if (hdr.ipv4.isValid() && hdr.ipv4.isValid()) {
                                hdr.ipv4.srcAddr = hdr.ipv4.dstAddr;
                            }
                            else {
                                bug();
                            }
                            if (hdr.ipv4.isValid()) {
                                hdr.ipv4.dstAddr = meta._reply_to_client_md_ipv4_dstAddr5;
                            }
                            else {
                                bug();
                            }
                            if (hdr.nc_hdr.isValid()) {
                                hdr.nc_hdr.op = gen_reply.gen_reply_act__message_type;
                            }
                            else {
                                bug();
                            }
                            if (hdr.udp.isValid()) {
                                hdr.udp.dstPort = 16w8889;
                            }
                            else {
                                bug();
                            }
                        }
                        else {
                            ;
                        }
                        end_gen_reply_0();
                    }
                    else {
                        tmp_25 = query_get_next_hop_0();
                        get_next_hop = tmp_25;
                        if (get_next_hop.action_run == flow_def_get_next_hop_0__action_type_t.get_next_hop_act) {
                            angelic_assert(true);
                            if (hdr.overlay.elements[0].isValid() && hdr.ipv4.isValid()) {
                                hdr.ipv4.dstAddr = hdr.overlay.elements[0].swip;
                            }
                            else {
                                bug();
                            }
                        }
                        else {
                            ;
                        }
                        end_get_next_hop_0();
                    }
                }
            }
            else {
                bug();
            }
        }
        if (hdr.nc_hdr.isValid()) {
            tmp_26 = query_failure_recovery_0(hdr.ipv4.dstAddr, hdr.overlay.elements[1].swip, hdr.nc_hdr.vgroup);
            failure_recovery = tmp_26;
            if (failure_recovery.hit) {
                key_match(hdr.ipv4.dstAddr & failure_recovery.key_failure_recovery_0_ipv4_dstAddr__mask == failure_recovery.key_failure_recovery_0_ipv4_dstAddr__val & failure_recovery.key_failure_recovery_0_ipv4_dstAddr__mask && hdr.overlay.elements[1].swip & failure_recovery.key_failure_recovery_0_overlay_1__swip__mask == failure_recovery.key_failure_recovery_0_overlay_1__swip__val & failure_recovery.key_failure_recovery_0_overlay_1__swip__mask && hdr.nc_hdr.vgroup & failure_recovery.key_failure_recovery_0_nc_hdr_vgroup__mask == failure_recovery.key_failure_recovery_0_nc_hdr_vgroup__val & failure_recovery.key_failure_recovery_0_nc_hdr_vgroup__mask);
                if (!(hdr.ipv4.isValid() || failure_recovery.key_failure_recovery_0_ipv4_dstAddr__mask == 32w0)) {
                    bug();
                }
                if (!(hdr.overlay.elements[1].isValid() || failure_recovery.key_failure_recovery_0_overlay_1__swip__mask == 32w0)) {
                    bug();
                }
                if (!(hdr.nc_hdr.isValid() || failure_recovery.key_failure_recovery_0_nc_hdr_vgroup__mask == 16w0)) {
                    bug();
                }
            }
            if (failure_recovery.action_run == flow_def_failure_recovery_0__action_type_t.NoAction_17) {
                ;
            }
            else {
                if (failure_recovery.action_run == flow_def_failure_recovery_0__action_type_t.drop_packet_act_2) {
                    angelic_assert(true);
                    standard_metadata.egress_spec = 9w511;
                    __track_egress_spec_0 = true;
                }
                else {
                    if (failure_recovery.action_run == flow_def_failure_recovery_0__action_type_t.nop) {
                        angelic_assert(true);
                    }
                    else {
                        if (failure_recovery.action_run == flow_def_failure_recovery_0__action_type_t.failure_recovery_act) {
                            angelic_assert(true);
                            if (hdr.overlay.elements[0].isValid()) {
                                hdr.overlay.elements[0].swip = failure_recovery.failure_recovery_act__nexthop;
                            }
                            else {
                                bug();
                            }
                            if (hdr.ipv4.isValid()) {
                                hdr.ipv4.dstAddr = failure_recovery.failure_recovery_act__nexthop;
                            }
                            else {
                                bug();
                            }
                        }
                        else {
                            if (failure_recovery.action_run == flow_def_failure_recovery_0__action_type_t.failover_write_reply_act) {
                                angelic_assert(true);
                                if (hdr.ipv4.isValid()) {
                                    meta._reply_to_client_md_ipv4_srcAddr4 = hdr.ipv4.dstAddr;
                                }
                                else {
                                    bug();
                                }
                                if (hdr.ipv4.isValid()) {
                                    meta._reply_to_client_md_ipv4_dstAddr5 = hdr.ipv4.srcAddr;
                                }
                                else {
                                    bug();
                                }
                                if (hdr.ipv4.isValid() && hdr.ipv4.isValid()) {
                                    hdr.ipv4.srcAddr = hdr.ipv4.dstAddr;
                                }
                                else {
                                    bug();
                                }
                                if (hdr.ipv4.isValid()) {
                                    hdr.ipv4.dstAddr = meta._reply_to_client_md_ipv4_dstAddr5;
                                }
                                else {
                                    bug();
                                }
                                if (hdr.nc_hdr.isValid()) {
                                    hdr.nc_hdr.op = 8w13;
                                }
                                else {
                                    bug();
                                }
                                if (hdr.udp.isValid()) {
                                    hdr.udp.dstPort = 16w8889;
                                }
                                else {
                                    bug();
                                }
                            }
                            else {
                                if (failure_recovery.action_run == flow_def_failure_recovery_0__action_type_t.failover_act) {
                                    angelic_assert(true);
                                    if (hdr.overlay.elements[1].isValid() && hdr.ipv4.isValid()) {
                                        hdr.ipv4.dstAddr = hdr.overlay.elements[1].swip;
                                    }
                                    else {
                                        bug();
                                    }
                                    if (hdr.nc_hdr.isValid() && hdr.nc_hdr.isValid()) {
                                        hdr.nc_hdr.sc = hdr.nc_hdr.sc + 8w255;
                                    }
                                    else {
                                        bug();
                                    }
                                    hdr.overlay.elements[0] = hdr.overlay.elements[1];
                                    hdr.overlay.elements[1] = hdr.overlay.elements[2];
                                    hdr.overlay.elements[2] = hdr.overlay.elements[3];
                                    hdr.overlay.elements[3] = hdr.overlay.elements[4];
                                    hdr.overlay.elements[4] = hdr.overlay.elements[5];
                                    hdr.overlay.elements[5] = hdr.overlay.elements[6];
                                    hdr.overlay.elements[6] = hdr.overlay.elements[7];
                                    hdr.overlay.elements[7] = hdr.overlay.elements[8];
                                    hdr.overlay.elements[8] = hdr.overlay.elements[9];
                                    hdr.overlay.elements[9].setInvalid();
                                    if (hdr.overlay.nxt < 16w1) {
                                        hdr.overlay.nxt = 16w0;
                                    }
                                    else {
                                        hdr.overlay.nxt = hdr.overlay.nxt + 16w65535;
                                    }
                                    if (hdr.udp.isValid() && hdr.udp.isValid()) {
                                        hdr.udp.len = hdr.udp.len + 16w65532;
                                    }
                                    else {
                                        bug();
                                    }
                                    if (hdr.ipv4.isValid() && hdr.ipv4.isValid()) {
                                        hdr.ipv4.totalLen = hdr.ipv4.totalLen + 16w65532;
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
                }
            }
            end_failure_recovery_0();
        }
        if (hdr.tcp.isValid() || hdr.udp.isValid()) {
            tmp_27 = query_ipv4_route_0(hdr.ipv4.dstAddr);
            ipv4_route = tmp_27;
            if (ipv4_route.hit) {
                key_match(hdr.ipv4.dstAddr == ipv4_route.key_ipv4_route_0_ipv4_dstAddr);
                if (!hdr.ipv4.isValid()) {
                    bug();
                }
            }
            if (ipv4_route.action_run == flow_def_ipv4_route_0__action_type_t.NoAction_23) {
                ;
            }
            else {
                if (ipv4_route.action_run == flow_def_ipv4_route_0__action_type_t.set_egress) {
                    angelic_assert(true);
                    standard_metadata.egress_spec = ipv4_route.set_egress__egress_spec;
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
            end_ipv4_route_0();
        }
        if (!__track_egress_spec_0) {
            bug();
        }
    }
}

control DeparserImpl(mutable_packet packet, in headers hdr) {
    apply {
        packet.emit<ethernet_t>(hdr.ethernet);
        packet.emit<ipv4_t>(hdr.ipv4);
        packet.emit<udp_t>(hdr.udp);
        packet.emit<overlay_t>(hdr.overlay.elements[0]);
        packet.emit<overlay_t>(hdr.overlay.elements[1]);
        packet.emit<overlay_t>(hdr.overlay.elements[2]);
        packet.emit<overlay_t>(hdr.overlay.elements[3]);
        packet.emit<overlay_t>(hdr.overlay.elements[4]);
        packet.emit<overlay_t>(hdr.overlay.elements[5]);
        packet.emit<overlay_t>(hdr.overlay.elements[6]);
        packet.emit<overlay_t>(hdr.overlay.elements[7]);
        packet.emit<overlay_t>(hdr.overlay.elements[8]);
        packet.emit<overlay_t>(hdr.overlay.elements[9]);
        packet.emit<nc_hdr_t>(hdr.nc_hdr);
        packet.emit<tcp_t>(hdr.tcp);
    }
}

control verifyChecksum(inout headers hdr, inout metadata meta) {
    apply {
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
    bit<16> field_17;
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
            clone_metas_0._location_index0 = 16w0;
            clone_metas_0._my_md_ipaddress1 = 32w0;
            clone_metas_0._my_md_role2 = 16w0;
            clone_metas_0._my_md_failed3 = 16w0;
            clone_metas_0._reply_to_client_md_ipv4_srcAddr4 = 32w0;
            clone_metas_0._reply_to_client_md_ipv4_dstAddr5 = 32w0;
            clone_metas_0._sequence_md_seq6 = 16w0;
            clone_metas_0._sequence_md_tmp7 = 16w0;
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
        hdrs.nc_hdr.setInvalid();
        hdrs.tcp.setInvalid();
        hdrs.udp.setInvalid();
        hdrs.overlay.nxt = 16w0;
        hdrs.overlay.elements[0].setInvalid();
        hdrs.overlay.elements[1].setInvalid();
        hdrs.overlay.elements[2].setInvalid();
        hdrs.overlay.elements[3].setInvalid();
        hdrs.overlay.elements[4].setInvalid();
        hdrs.overlay.elements[5].setInvalid();
        hdrs.overlay.elements[6].setInvalid();
        hdrs.overlay.elements[7].setInvalid();
        hdrs.overlay.elements[8].setInvalid();
        hdrs.overlay.elements[9].setInvalid();
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
        metas._location_index0 = 16w0;
        metas._my_md_ipaddress1 = 32w0;
        metas._my_md_role2 = 16w0;
        metas._my_md_failed3 = 16w0;
        metas._reply_to_client_md_ipv4_srcAddr4 = 32w0;
        metas._reply_to_client_md_ipv4_dstAddr5 = 32w0;
        metas._sequence_md_seq6 = 16w0;
        metas._sequence_md_tmp7 = 16w0;
    }
    standard_meta_0.instance_type = PKT_INSTANCE_TYPE_NORMAL_0;
    parse_and_run(pin, metas, standard_meta_0);
}
