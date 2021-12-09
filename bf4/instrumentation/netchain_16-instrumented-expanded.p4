enum flow_def_drop_packet_0__action_type_t {
    drop_packet_act
}

struct flow_def_drop_packet_0 {
    bool                                  hit;
    bool                                  reach;
    flow_def_drop_packet_0__action_type_t action_run;
}

@controlled() extern flow_def_drop_packet_0 query_drop_packet_0();
extern void end_drop_packet_0();
enum flow_def_assign_value_0__action_type_t {
    assign_value_act
}

struct flow_def_assign_value_0 {
    bool                                   hit;
    bool                                   reach;
    flow_def_assign_value_0__action_type_t action_run;
}

@controlled() extern flow_def_assign_value_0 query_assign_value_0();
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

@controlled() extern flow_def_ethernet_set_mac_0 query_ethernet_set_mac_0(@matchKind("exact") in bit<9> ethernet_set_mac_0_standard_metadata_egress_port);
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

@controlled() extern flow_def_get_my_address_0 query_get_my_address_0(@matchKind("exact") in bit<128> get_my_address_0_nc_hdr_key);
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

@controlled() extern flow_def_gen_reply_0 query_gen_reply_0(@matchKind("exact") in bit<8> gen_reply_0_nc_hdr_op);
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

@controlled() extern flow_def_find_index_0 query_find_index_0(@matchKind("exact") in bit<128> find_index_0_nc_hdr_key);
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

@controlled() extern flow_def_failure_recovery_0 query_failure_recovery_0(@matchKind("ternary") in bit<32> failure_recovery_0_ipv4_dstAddr, @matchKind("ternary") in bit<32> failure_recovery_0_overlay_1__swip, @matchKind("ternary") in bit<16> failure_recovery_0_nc_hdr_vgroup);
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

@controlled() extern flow_def_ipv4_route_0 query_ipv4_route_0(@matchKind("exact") in bit<32> ipv4_route_0_ipv4_dstAddr);
extern void end_ipv4_route_0();
enum flow_def_read_value_0__action_type_t {
    read_value_act
}

struct flow_def_read_value_0 {
    bool                                 hit;
    bool                                 reach;
    flow_def_read_value_0__action_type_t action_run;
}

@controlled() extern flow_def_read_value_0 query_read_value_0();
extern void end_read_value_0();
enum flow_def_pop_chain_again_0__action_type_t {
    pop_chain_act_2
}

struct flow_def_pop_chain_again_0 {
    bool                                      hit;
    bool                                      reach;
    flow_def_pop_chain_again_0__action_type_t action_run;
}

@controlled() extern flow_def_pop_chain_again_0 query_pop_chain_again_0();
extern void end_pop_chain_again_0();
enum flow_def_pop_chain_0__action_type_t {
    pop_chain_act
}

struct flow_def_pop_chain_0 {
    bool                                hit;
    bool                                reach;
    flow_def_pop_chain_0__action_type_t action_run;
}

@controlled() extern flow_def_pop_chain_0 query_pop_chain_0();
extern void end_pop_chain_0();
enum flow_def_maintain_sequence_0__action_type_t {
    maintain_sequence_act
}

struct flow_def_maintain_sequence_0 {
    bool                                        hit;
    bool                                        reach;
    flow_def_maintain_sequence_0__action_type_t action_run;
}

@controlled() extern flow_def_maintain_sequence_0 query_maintain_sequence_0();
extern void end_maintain_sequence_0();
enum flow_def_get_sequence_0__action_type_t {
    get_sequence_act
}

struct flow_def_get_sequence_0 {
    bool                                   hit;
    bool                                   reach;
    flow_def_get_sequence_0__action_type_t action_run;
}

@controlled() extern flow_def_get_sequence_0 query_get_sequence_0();
extern void end_get_sequence_0();
enum flow_def_get_next_hop_0__action_type_t {
    get_next_hop_act
}

struct flow_def_get_next_hop_0 {
    bool                                   hit;
    bool                                   reach;
    flow_def_get_next_hop_0__action_type_t action_run;
}

@controlled() extern flow_def_get_next_hop_0 query_get_next_hop_0();
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

@array() struct overlay_t_10 {
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
        hdr.overlay.nxt = (bit<16>)16w0;
        transition parse_ethernet;
    }
    state parse_overlay_0 {
        packet.extract<overlay_t>(hdr.overlay.elements[hdr.overlay.nxt]);
        hdr.overlay.nxt = hdr.overlay.nxt + 16w1;
        transition select(hdr.overlay.elements[hdr.overlay.nxt - 16w1].swip) {
            32w0: parse_nc_hdr;
            default: parse_overlay;
        }
    }
}

control egress(inout headers hdr, inout metadata meta, inout standard_metadata_t standard_metadata) {
    apply {
        {
            flow_def_ethernet_set_mac_0 ethernet_set_mac;
            ethernet_set_mac = query_ethernet_set_mac_0(standard_metadata.egress_port);
            if (ethernet_set_mac.hit) {
                key_match(standard_metadata.egress_port == ethernet_set_mac.key_ethernet_set_mac_0_standard_metadata_egress_port);
            }
            if (ethernet_set_mac.action_run == flow_def_ethernet_set_mac_0__action_type_t.ethernet_set_mac_act) {
                angelic_assert(true);
                {
                    if (hdr.ethernet.isValid())  {
                        hdr.ethernet.srcAddr = ethernet_set_mac.ethernet_set_mac_act__smac;
                    } 
                    else  {
                        bug();
                    }
                    if (hdr.ethernet.isValid())  {
                        hdr.ethernet.dstAddr = ethernet_set_mac.ethernet_set_mac_act__dmac;
                    } 
                    else  {
                        bug();
                    }
                }
            }
            else  {
                ;
            }
            end_ethernet_set_mac_0();
        }
    }
}

control ingress(inout headers hdr, inout metadata meta, inout standard_metadata_t standard_metadata) {
    bool __track_egress_spec_0;
    @name(".sequence_reg") register<bit<16>>(32w4096) sequence_reg_0;
    @name(".value_reg") register<bit<128>>(32w4096) value_reg_0;
    apply {
        __track_egress_spec_0 = false;
        if (hdr.nc_hdr.isValid()) {
            {
                flow_def_get_my_address_0 get_my_address;
                get_my_address = query_get_my_address_0(hdr.nc_hdr.key);
                if (get_my_address.hit) {
                    key_match(hdr.nc_hdr.key == get_my_address.key_get_my_address_0_nc_hdr_key);
                    if (!hdr.nc_hdr.isValid())  {
                        bug();
                    } 
                }
                if (get_my_address.action_run == flow_def_get_my_address_0__action_type_t.get_my_address_act) {
                    angelic_assert(true);
                    {
                        meta._my_md_ipaddress1 = get_my_address.get_my_address_act__sw_ip;
                        meta._my_md_role2 = get_my_address.get_my_address_act__sw_role;
                    }
                }
                else  {
                    ;
                }
                end_get_my_address_0();
            }
            if (hdr.ipv4.isValid())  {
                if (hdr.ipv4.dstAddr == meta._my_md_ipaddress1) {
                    {
                        flow_def_find_index_0 find_index;
                        find_index = query_find_index_0(hdr.nc_hdr.key);
                        if (find_index.hit) {
                            key_match(hdr.nc_hdr.key == find_index.key_find_index_0_nc_hdr_key);
                            if (!hdr.nc_hdr.isValid())  {
                                bug();
                            } 
                        }
                        if (find_index.action_run == flow_def_find_index_0__action_type_t.find_index_act) {
                            angelic_assert(true);
                            {
                                meta._location_index0 = find_index.find_index_act__index;
                            }
                        }
                        else  {
                            ;
                        }
                        end_find_index_0();
                    }
                    {
                        flow_def_get_sequence_0 get_sequence;
                        get_sequence = query_get_sequence_0();
                        ;
                        if (get_sequence.action_run == flow_def_get_sequence_0__action_type_t.get_sequence_act) {
                            angelic_assert(true);
                            {
                                if ((bit<32>)meta._location_index0 >= 32w4096)  {
                                    bug();
                                } 
                                sequence_reg_0.read(meta._sequence_md_seq6, (bit<32>)meta._location_index0);
                            }
                        }
                        else  {
                            ;
                        }
                        end_get_sequence_0();
                    }
                    if (hdr.nc_hdr.isValid())  {
                        if (hdr.nc_hdr.op == 8w10) {
                            flow_def_read_value_0 read_value;
                            read_value = query_read_value_0();
                            ;
                            if (read_value.action_run == flow_def_read_value_0__action_type_t.read_value_act) {
                                angelic_assert(true);
                                {
                                    if ((bit<32>)meta._location_index0 >= 32w4096)  {
                                        bug();
                                    } 
                                    value_reg_0.read(hdr.nc_hdr.value, (bit<32>)meta._location_index0);
                                }
                            }
                            else  {
                                ;
                            }
                            end_read_value_0();
                        }
                        else  {
                            if (hdr.nc_hdr.isValid())  {
                                if (hdr.nc_hdr.op == 8w12) {
                                    if (meta._my_md_role2 == 16w100) {
                                        flow_def_maintain_sequence_0 maintain_sequence;
                                        maintain_sequence = query_maintain_sequence_0();
                                        ;
                                        if (maintain_sequence.action_run == flow_def_maintain_sequence_0__action_type_t.maintain_sequence_act) {
                                            angelic_assert(true);
                                            {
                                                meta._sequence_md_seq6 = meta._sequence_md_seq6 + 16w1;
                                                if ((bit<32>)meta._location_index0 >= 32w4096)  {
                                                    bug();
                                                } 
                                                sequence_reg_0.write((bit<32>)meta._location_index0, meta._sequence_md_seq6);
                                                if ((bit<32>)meta._location_index0 >= 32w4096)  {
                                                    bug();
                                                } 
                                                sequence_reg_0.read(hdr.nc_hdr.seq, (bit<32>)meta._location_index0);
                                            }
                                        }
                                        else  {
                                            ;
                                        }
                                        end_maintain_sequence_0();
                                    }
                                    if (hdr.nc_hdr.isValid() || meta._my_md_role2 == 16w100)  {
                                        if (meta._my_md_role2 == 16w100 || hdr.nc_hdr.seq > meta._sequence_md_seq6) {
                                            {
                                                flow_def_assign_value_0 assign_value;
                                                assign_value = query_assign_value_0();
                                                ;
                                                if (assign_value.action_run == flow_def_assign_value_0__action_type_t.assign_value_act) {
                                                    angelic_assert(true);
                                                    {
                                                        if (hdr.nc_hdr.isValid()) {
                                                            if ((bit<32>)meta._location_index0 >= 32w4096)  {
                                                                bug();
                                                            } 
                                                            sequence_reg_0.write((bit<32>)meta._location_index0, hdr.nc_hdr.seq);
                                                        }
                                                        else  {
                                                            bug();
                                                        }
                                                        if (hdr.nc_hdr.isValid()) {
                                                            if ((bit<32>)meta._location_index0 >= 32w4096)  {
                                                                bug();
                                                            } 
                                                            value_reg_0.write((bit<32>)meta._location_index0, hdr.nc_hdr.value);
                                                        }
                                                        else  {
                                                            bug();
                                                        }
                                                    }
                                                }
                                                else  {
                                                    ;
                                                }
                                                end_assign_value_0();
                                            }
                                            {
                                                flow_def_pop_chain_0 pop_chain;
                                                pop_chain = query_pop_chain_0();
                                                ;
                                                if (pop_chain.action_run == flow_def_pop_chain_0__action_type_t.pop_chain_act) {
                                                    angelic_assert(true);
                                                    {
                                                        if (hdr.nc_hdr.isValid() && hdr.nc_hdr.isValid())  {
                                                            hdr.nc_hdr.sc = hdr.nc_hdr.sc + 8w255;
                                                        } 
                                                        else  {
                                                            bug();
                                                        }
                                                        {
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
                                                            if (hdr.overlay.nxt < 16w1)  {
                                                                hdr.overlay.nxt = (bit<16>)16w0;
                                                            } 
                                                            else  {
                                                                hdr.overlay.nxt = hdr.overlay.nxt - 16w1;
                                                            }
                                                        }
                                                        if (hdr.udp.isValid() && hdr.udp.isValid())  {
                                                            hdr.udp.len = hdr.udp.len + 16w65532;
                                                        } 
                                                        else  {
                                                            bug();
                                                        }
                                                        if (hdr.ipv4.isValid() && hdr.ipv4.isValid())  {
                                                            hdr.ipv4.totalLen = hdr.ipv4.totalLen + 16w65532;
                                                        } 
                                                        else  {
                                                            bug();
                                                        }
                                                    }
                                                }
                                                else  {
                                                    ;
                                                }
                                                end_pop_chain_0();
                                            }
                                        }
                                        else {
                                            flow_def_drop_packet_0 drop_packet;
                                            drop_packet = query_drop_packet_0();
                                            ;
                                            if (drop_packet.action_run == flow_def_drop_packet_0__action_type_t.drop_packet_act) {
                                                angelic_assert(true);
                                                {
                                                    standard_metadata.egress_spec = 9w511;
                                                    __track_egress_spec_0 = true;
                                                }
                                            }
                                            else  {
                                                ;
                                            }
                                            end_drop_packet_0();
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
                    else  {
                        bug();
                    }
                    if (meta._my_md_role2 == 16w102) {
                        {
                            flow_def_pop_chain_again_0 pop_chain_again;
                            pop_chain_again = query_pop_chain_again_0();
                            ;
                            if (pop_chain_again.action_run == flow_def_pop_chain_again_0__action_type_t.pop_chain_act_2) {
                                angelic_assert(true);
                                {
                                    if (hdr.nc_hdr.isValid() && hdr.nc_hdr.isValid())  {
                                        hdr.nc_hdr.sc = hdr.nc_hdr.sc + 8w255;
                                    } 
                                    else  {
                                        bug();
                                    }
                                    {
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
                                        if (hdr.overlay.nxt < 16w1)  {
                                            hdr.overlay.nxt = (bit<16>)16w0;
                                        } 
                                        else  {
                                            hdr.overlay.nxt = hdr.overlay.nxt - 16w1;
                                        }
                                    }
                                    if (hdr.udp.isValid() && hdr.udp.isValid())  {
                                        hdr.udp.len = hdr.udp.len + 16w65532;
                                    } 
                                    else  {
                                        bug();
                                    }
                                    if (hdr.ipv4.isValid() && hdr.ipv4.isValid())  {
                                        hdr.ipv4.totalLen = hdr.ipv4.totalLen + 16w65532;
                                    } 
                                    else  {
                                        bug();
                                    }
                                }
                            }
                            else  {
                                ;
                            }
                            end_pop_chain_again_0();
                        }
                        {
                            flow_def_gen_reply_0 gen_reply;
                            gen_reply = query_gen_reply_0(hdr.nc_hdr.op);
                            if (gen_reply.hit) {
                                key_match(hdr.nc_hdr.op == gen_reply.key_gen_reply_0_nc_hdr_op);
                                if (!hdr.nc_hdr.isValid())  {
                                    bug();
                                } 
                            }
                            if (gen_reply.action_run == flow_def_gen_reply_0__action_type_t.gen_reply_act) {
                                angelic_assert(true);
                                {
                                    if (hdr.ipv4.isValid())  {
                                        meta._reply_to_client_md_ipv4_srcAddr4 = hdr.ipv4.dstAddr;
                                    } 
                                    else  {
                                        bug();
                                    }
                                    if (hdr.ipv4.isValid())  {
                                        meta._reply_to_client_md_ipv4_dstAddr5 = hdr.ipv4.srcAddr;
                                    } 
                                    else  {
                                        bug();
                                    }
                                    if (hdr.ipv4.isValid() && hdr.ipv4.isValid())  {
                                        hdr.ipv4.srcAddr = hdr.ipv4.dstAddr;
                                    } 
                                    else  {
                                        bug();
                                    }
                                    if (hdr.ipv4.isValid())  {
                                        hdr.ipv4.dstAddr = meta._reply_to_client_md_ipv4_dstAddr5;
                                    } 
                                    else  {
                                        bug();
                                    }
                                    if (hdr.nc_hdr.isValid())  {
                                        hdr.nc_hdr.op = gen_reply.gen_reply_act__message_type;
                                    } 
                                    else  {
                                        bug();
                                    }
                                    if (hdr.udp.isValid())  {
                                        hdr.udp.dstPort = 16w8889;
                                    } 
                                    else  {
                                        bug();
                                    }
                                }
                            }
                            else  {
                                ;
                            }
                            end_gen_reply_0();
                        }
                    }
                    else {
                        flow_def_get_next_hop_0 get_next_hop;
                        get_next_hop = query_get_next_hop_0();
                        ;
                        if (get_next_hop.action_run == flow_def_get_next_hop_0__action_type_t.get_next_hop_act) {
                            angelic_assert(true);
                            {
                                if (hdr.overlay.elements[0].isValid() && hdr.ipv4.isValid())  {
                                    hdr.ipv4.dstAddr = hdr.overlay.elements[0].swip;
                                } 
                                else  {
                                    bug();
                                }
                            }
                        }
                        else  {
                            ;
                        }
                        end_get_next_hop_0();
                    }
                }
            } 
            else  {
                bug();
            }
        }
        if (hdr.nc_hdr.isValid()) {
            flow_def_failure_recovery_0 failure_recovery;
            failure_recovery = query_failure_recovery_0(hdr.ipv4.dstAddr, hdr.overlay.elements[1].swip, hdr.nc_hdr.vgroup);
            if (failure_recovery.hit) {
                key_match(hdr.ipv4.dstAddr & failure_recovery.key_failure_recovery_0_ipv4_dstAddr__mask == failure_recovery.key_failure_recovery_0_ipv4_dstAddr__val & failure_recovery.key_failure_recovery_0_ipv4_dstAddr__mask && hdr.overlay.elements[1].swip & failure_recovery.key_failure_recovery_0_overlay_1__swip__mask == failure_recovery.key_failure_recovery_0_overlay_1__swip__val & failure_recovery.key_failure_recovery_0_overlay_1__swip__mask && hdr.nc_hdr.vgroup & failure_recovery.key_failure_recovery_0_nc_hdr_vgroup__mask == failure_recovery.key_failure_recovery_0_nc_hdr_vgroup__val & failure_recovery.key_failure_recovery_0_nc_hdr_vgroup__mask);
                if (!(hdr.ipv4.isValid() || failure_recovery.key_failure_recovery_0_ipv4_dstAddr__mask == 32w0))  {
                    bug();
                } 
                if (!(hdr.overlay.elements[1].isValid() || failure_recovery.key_failure_recovery_0_overlay_1__swip__mask == 32w0))  {
                    bug();
                } 
                if (!(hdr.nc_hdr.isValid() || failure_recovery.key_failure_recovery_0_nc_hdr_vgroup__mask == 16w0))  {
                    bug();
                } 
            }
            if (failure_recovery.action_run == flow_def_failure_recovery_0__action_type_t.NoAction_17) {
            }
            else  {
                if (failure_recovery.action_run == flow_def_failure_recovery_0__action_type_t.drop_packet_act_2) {
                    angelic_assert(true);
                    {
                        standard_metadata.egress_spec = 9w511;
                        __track_egress_spec_0 = true;
                    }
                }
                else  {
                    if (failure_recovery.action_run == flow_def_failure_recovery_0__action_type_t.nop) {
                        angelic_assert(true);
                        {
                        }
                    }
                    else  {
                        if (failure_recovery.action_run == flow_def_failure_recovery_0__action_type_t.failure_recovery_act) {
                            angelic_assert(true);
                            {
                                if (hdr.overlay.elements[0].isValid())  {
                                    hdr.overlay.elements[0].swip = failure_recovery.failure_recovery_act__nexthop;
                                } 
                                else  {
                                    bug();
                                }
                                if (hdr.ipv4.isValid())  {
                                    hdr.ipv4.dstAddr = failure_recovery.failure_recovery_act__nexthop;
                                } 
                                else  {
                                    bug();
                                }
                            }
                        }
                        else  {
                            if (failure_recovery.action_run == flow_def_failure_recovery_0__action_type_t.failover_write_reply_act) {
                                angelic_assert(true);
                                {
                                    if (hdr.ipv4.isValid())  {
                                        meta._reply_to_client_md_ipv4_srcAddr4 = hdr.ipv4.dstAddr;
                                    } 
                                    else  {
                                        bug();
                                    }
                                    if (hdr.ipv4.isValid())  {
                                        meta._reply_to_client_md_ipv4_dstAddr5 = hdr.ipv4.srcAddr;
                                    } 
                                    else  {
                                        bug();
                                    }
                                    if (hdr.ipv4.isValid() && hdr.ipv4.isValid())  {
                                        hdr.ipv4.srcAddr = hdr.ipv4.dstAddr;
                                    } 
                                    else  {
                                        bug();
                                    }
                                    if (hdr.ipv4.isValid())  {
                                        hdr.ipv4.dstAddr = meta._reply_to_client_md_ipv4_dstAddr5;
                                    } 
                                    else  {
                                        bug();
                                    }
                                    if (hdr.nc_hdr.isValid())  {
                                        hdr.nc_hdr.op = 8w13;
                                    } 
                                    else  {
                                        bug();
                                    }
                                    if (hdr.udp.isValid())  {
                                        hdr.udp.dstPort = 16w8889;
                                    } 
                                    else  {
                                        bug();
                                    }
                                }
                            }
                            else  {
                                if (failure_recovery.action_run == flow_def_failure_recovery_0__action_type_t.failover_act) {
                                    angelic_assert(true);
                                    {
                                        if (hdr.overlay.elements[1].isValid() && hdr.ipv4.isValid())  {
                                            hdr.ipv4.dstAddr = hdr.overlay.elements[1].swip;
                                        } 
                                        else  {
                                            bug();
                                        }
                                        if (hdr.nc_hdr.isValid() && hdr.nc_hdr.isValid())  {
                                            hdr.nc_hdr.sc = hdr.nc_hdr.sc + 8w255;
                                        } 
                                        else  {
                                            bug();
                                        }
                                        {
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
                                            if (hdr.overlay.nxt < 16w1)  {
                                                hdr.overlay.nxt = (bit<16>)16w0;
                                            } 
                                            else  {
                                                hdr.overlay.nxt = hdr.overlay.nxt - 16w1;
                                            }
                                        }
                                        if (hdr.udp.isValid() && hdr.udp.isValid())  {
                                            hdr.udp.len = hdr.udp.len + 16w65532;
                                        } 
                                        else  {
                                            bug();
                                        }
                                        if (hdr.ipv4.isValid() && hdr.ipv4.isValid())  {
                                            hdr.ipv4.totalLen = hdr.ipv4.totalLen + 16w65532;
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
                }
            }
            end_failure_recovery_0();
        }
        if (hdr.tcp.isValid() || hdr.udp.isValid()) {
            flow_def_ipv4_route_0 ipv4_route;
            ipv4_route = query_ipv4_route_0(hdr.ipv4.dstAddr);
            if (ipv4_route.hit) {
                key_match(hdr.ipv4.dstAddr == ipv4_route.key_ipv4_route_0_ipv4_dstAddr);
                if (!hdr.ipv4.isValid())  {
                    bug();
                } 
            }
            if (ipv4_route.action_run == flow_def_ipv4_route_0__action_type_t.NoAction_23) {
            }
            else  {
                if (ipv4_route.action_run == flow_def_ipv4_route_0__action_type_t.set_egress) {
                    angelic_assert(true);
                    {
                        standard_metadata.egress_spec = ipv4_route.set_egress__egress_spec;
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
            end_ipv4_route_0();
        }
        if (!__track_egress_spec_0)  {
            bug();
        } 
    }
}

control DeparserImpl(packet_out packet, in headers hdr) {
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
