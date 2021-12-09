
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

struct headers {
    @name(".ethernet") 
    ethernet_t    ethernet;
    @name(".ipv4") 
    ipv4_t        ipv4;
    @name(".nc_hdr") 
    nc_hdr_t      nc_hdr;
    @name(".tcp") 
    tcp_t         tcp;
    @name(".udp") 
    udp_t         udp;
    @name(".overlay") 
    overlay_t[10] overlay;
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
    @name(".parse_overlay") state parse_overlay {
        packet.extract<overlay_t>(hdr.overlay.next);
        transition select(hdr.overlay.last.swip) {
            32w0: parse_nc_hdr;
            default: parse_overlay;
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
        transition parse_ethernet;
    }
}

control egress(inout headers hdr, inout metadata meta, inout standard_metadata_t standard_metadata) {
    @name(".NoAction") action NoAction_0() {
    }
    @name(".ethernet_set_mac_act") action ethernet_set_mac_act(bit<48> smac, bit<48> dmac) {
        hdr.ethernet.srcAddr = smac;
        hdr.ethernet.dstAddr = dmac;
    }
    @name(".ethernet_set_mac") table ethernet_set_mac_0 {
        actions = {
            ethernet_set_mac_act();
            @defaultonly NoAction_0();
        }
        key = {
            standard_metadata.egress_port: exact @name("standard_metadata.egress_port") ;
        }
        default_action = NoAction_0();
    }
    apply {
        ethernet_set_mac_0.apply();
    }
}

@name(".sequence_reg") register<bit<16>>(32w4096) sequence_reg;

@name(".value_reg") register<bit<128>>(32w4096) value_reg;

control ingress(inout headers hdr, inout metadata meta, inout standard_metadata_t standard_metadata) {
    @name(".NoAction") action NoAction_1() {
    }
    @name(".NoAction") action NoAction_16() {
    }
    @name(".NoAction") action NoAction_17() {
    }
    @name(".NoAction") action NoAction_18() {
    }
    @name(".NoAction") action NoAction_19() {
    }
    @name(".NoAction") action NoAction_20() {
    }
    @name(".NoAction") action NoAction_21() {
    }
    @name(".NoAction") action NoAction_22() {
    }
    @name(".NoAction") action NoAction_23() {
    }
    @name(".NoAction") action NoAction_24() {
    }
    @name(".NoAction") action NoAction_25() {
    }
    @name(".NoAction") action NoAction_26() {
    }
    @name(".NoAction") action NoAction_27() {
    }
    @name(".assign_value_act") action assign_value_act() {
        sequence_reg.write((bit<32>)meta._location_index0, hdr.nc_hdr.seq);
        value_reg.write((bit<32>)meta._location_index0, hdr.nc_hdr.value);
    }
    @name(".drop_packet_act") action drop_packet_act() {
        standard_metadata.egress_spec = 9w511;
    }
    @name(".drop_packet_act") action drop_packet_act_2() {
        standard_metadata.egress_spec = 9w511;
    }
    @name(".pop_chain_act") action pop_chain_act() {
        hdr.nc_hdr.sc = hdr.nc_hdr.sc + 8w255;
        hdr.overlay.pop_front(1);
        hdr.udp.len = hdr.udp.len + 16w65532;
        hdr.ipv4.totalLen = hdr.ipv4.totalLen + 16w65532;
    }
    @name(".pop_chain_act") action pop_chain_act_2() {
        hdr.nc_hdr.sc = hdr.nc_hdr.sc + 8w255;
        hdr.overlay.pop_front(1);
        hdr.udp.len = hdr.udp.len + 16w65532;
        hdr.ipv4.totalLen = hdr.ipv4.totalLen + 16w65532;
    }
    @name(".failover_act") action failover_act() {
        hdr.ipv4.dstAddr = hdr.overlay[1].swip;
        hdr.nc_hdr.sc = hdr.nc_hdr.sc + 8w255;
        hdr.overlay.pop_front(1);
        hdr.udp.len = hdr.udp.len + 16w65532;
        hdr.ipv4.totalLen = hdr.ipv4.totalLen + 16w65532;
    }
    @name(".gen_reply_act") action gen_reply_act(bit<8> message_type) {
        meta._reply_to_client_md_ipv4_srcAddr4 = hdr.ipv4.dstAddr;
        meta._reply_to_client_md_ipv4_dstAddr5 = hdr.ipv4.srcAddr;
        hdr.ipv4.srcAddr = hdr.ipv4.dstAddr;
        hdr.ipv4.dstAddr = meta._reply_to_client_md_ipv4_dstAddr5;
        hdr.nc_hdr.op = message_type;
        hdr.udp.dstPort = 16w8889;
    }
    @name(".failover_write_reply_act") action failover_write_reply_act() {
        meta._reply_to_client_md_ipv4_srcAddr4 = hdr.ipv4.dstAddr;
        meta._reply_to_client_md_ipv4_dstAddr5 = hdr.ipv4.srcAddr;
        hdr.ipv4.srcAddr = hdr.ipv4.dstAddr;
        hdr.ipv4.dstAddr = meta._reply_to_client_md_ipv4_dstAddr5;
        hdr.nc_hdr.op = 8w13;
        hdr.udp.dstPort = 16w8889;
    }
    @name(".failure_recovery_act") action failure_recovery_act(bit<32> nexthop) {
        hdr.overlay[0].swip = nexthop;
        hdr.ipv4.dstAddr = nexthop;
    }
    @name(".nop") action nop() {
    }
    @name(".find_index_act") action find_index_act(bit<16> index) {
        meta._location_index0 = index;
    }
    @name(".get_my_address_act") action get_my_address_act(bit<32> sw_ip, bit<16> sw_role) {
        meta._my_md_ipaddress1 = sw_ip;
        meta._my_md_role2 = sw_role;
    }
    @name(".get_next_hop_act") action get_next_hop_act() {
        hdr.ipv4.dstAddr = hdr.overlay[0].swip;
    }
    @name(".get_sequence_act") action get_sequence_act() {
        sequence_reg.read(meta._sequence_md_seq6, (bit<32>)meta._location_index0);
    }
    @name(".set_egress") action set_egress(bit<9> egress_spec) {
        standard_metadata.egress_spec = egress_spec;
        hdr.ipv4.ttl = hdr.ipv4.ttl + 8w255;
    }
    @name(".maintain_sequence_act") action maintain_sequence_act() {
        meta._sequence_md_seq6 = meta._sequence_md_seq6 + 16w1;
        sequence_reg.write((bit<32>)meta._location_index0, meta._sequence_md_seq6);
        sequence_reg.read(hdr.nc_hdr.seq, (bit<32>)meta._location_index0);
    }
    @name(".read_value_act") action read_value_act() {
        value_reg.read(hdr.nc_hdr.value, (bit<32>)meta._location_index0);
    }
    @name(".assign_value") table assign_value_0 {
        actions = {
            assign_value_act();
            @defaultonly NoAction_1();
        }
        default_action = NoAction_1();
    }
    @name(".drop_packet") table drop_packet_0 {
        actions = {
            drop_packet_act();
            @defaultonly NoAction_16();
        }
        default_action = NoAction_16();
    }
    @name(".failure_recovery") table failure_recovery_0 {
        actions = {
            failover_act();
            failover_write_reply_act();
            failure_recovery_act();
            nop();
            drop_packet_act_2();
            @defaultonly NoAction_17();
        }
        key = {
            hdr.ipv4.dstAddr   : ternary @name("ipv4.dstAddr") ;
            hdr.overlay[1].swip: ternary @name("overlay[1].swip") ;
            hdr.nc_hdr.vgroup  : ternary @name("nc_hdr.vgroup") ;
        }
        default_action = NoAction_17();
    }
    @name(".find_index") table find_index_0 {
        actions = {
            find_index_act();
            @defaultonly NoAction_18();
        }
        key = {
            hdr.nc_hdr.key: exact @name("nc_hdr.key") ;
        }
        default_action = NoAction_18();
    }
    @name(".gen_reply") table gen_reply_0 {
        actions = {
            gen_reply_act();
            @defaultonly NoAction_19();
        }
        key = {
            hdr.nc_hdr.op: exact @name("nc_hdr.op") ;
        }
        default_action = NoAction_19();
    }
    @name(".get_my_address") table get_my_address_0 {
        actions = {
            get_my_address_act();
            @defaultonly NoAction_20();
        }
        key = {
            hdr.nc_hdr.key: exact @name("nc_hdr.key") ;
        }
        default_action = NoAction_20();
    }
    @name(".get_next_hop") table get_next_hop_0 {
        actions = {
            get_next_hop_act();
            @defaultonly NoAction_21();
        }
        default_action = NoAction_21();
    }
    @name(".get_sequence") table get_sequence_0 {
        actions = {
            get_sequence_act();
            @defaultonly NoAction_22();
        }
        default_action = NoAction_22();
    }
    @stage(11) @name(".ipv4_route") table ipv4_route_0 {
        actions = {
            set_egress();
            @defaultonly NoAction_23();
        }
        key = {
            hdr.ipv4.dstAddr: exact @name("ipv4.dstAddr") ;
        }
        size = 8192;
        default_action = NoAction_23();
    }
    @name(".maintain_sequence") table maintain_sequence_0 {
        actions = {
            maintain_sequence_act();
            @defaultonly NoAction_24();
        }
        default_action = NoAction_24();
    }
    @name(".pop_chain") table pop_chain_0 {
        actions = {
            pop_chain_act();
            @defaultonly NoAction_25();
        }
        default_action = NoAction_25();
    }
    @name(".pop_chain_again") table pop_chain_again_0 {
        actions = {
            pop_chain_act_2();
            @defaultonly NoAction_26();
        }
        default_action = NoAction_26();
    }
    @name(".read_value") table read_value_0 {
        actions = {
            read_value_act();
            @defaultonly NoAction_27();
        }
        default_action = NoAction_27();
    }
    apply {
        if (hdr.nc_hdr.isValid()) {
            get_my_address_0.apply();
            if (hdr.ipv4.dstAddr == meta._my_md_ipaddress1) {
                find_index_0.apply();
                get_sequence_0.apply();
                if (hdr.nc_hdr.op == 8w10)  {
                    read_value_0.apply();
                } 
                else  {
                    if (hdr.nc_hdr.op == 8w12) {
                        if (meta._my_md_role2 == 16w100)  {
                            maintain_sequence_0.apply();
                        } 
                        if (meta._my_md_role2 == 16w100 || hdr.nc_hdr.seq > meta._sequence_md_seq6) {
                            assign_value_0.apply();
                            pop_chain_0.apply();
                        }
                        else  {
                            drop_packet_0.apply();
                        }
                    }
                }
                if (meta._my_md_role2 == 16w102) {
                    pop_chain_again_0.apply();
                    gen_reply_0.apply();
                }
                else  {
                    get_next_hop_0.apply();
                }
            }
        }
        if (hdr.nc_hdr.isValid())  {
            failure_recovery_0.apply();
        } 
        if (hdr.tcp.isValid() || hdr.udp.isValid())  {
            ipv4_route_0.apply();
        } 
    }
}

control DeparserImpl(packet_out packet, in headers hdr) {
    apply {
        packet.emit<ethernet_t>(hdr.ethernet);
        packet.emit<ipv4_t>(hdr.ipv4);
        packet.emit<udp_t>(hdr.udp);
        packet.emit<overlay_t>(hdr.overlay[0]);
        packet.emit<overlay_t>(hdr.overlay[1]);
        packet.emit<overlay_t>(hdr.overlay[2]);
        packet.emit<overlay_t>(hdr.overlay[3]);
        packet.emit<overlay_t>(hdr.overlay[4]);
        packet.emit<overlay_t>(hdr.overlay[5]);
        packet.emit<overlay_t>(hdr.overlay[6]);
        packet.emit<overlay_t>(hdr.overlay[7]);
        packet.emit<overlay_t>(hdr.overlay[8]);
        packet.emit<overlay_t>(hdr.overlay[9]);
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
        update_checksum<tuple_0, bit<16>>(true, { hdr.ipv4.version, hdr.ipv4.ihl, hdr.ipv4.diffserv, hdr.ipv4.totalLen, hdr.ipv4.identification, hdr.ipv4.flags, hdr.ipv4.fragOffset, hdr.ipv4.ttl, hdr.ipv4.protocol, hdr.ipv4.srcAddr, hdr.ipv4.dstAddr }, hdr.ipv4.hdrChecksum, HashAlgorithm.csum16);
        update_checksum_with_payload<tuple_1, bit<16>>(true, { hdr.ipv4.srcAddr, hdr.ipv4.dstAddr, 8w0, hdr.ipv4.protocol, hdr.udp.len, hdr.udp.srcPort, hdr.udp.dstPort, hdr.udp.len }, hdr.udp.checksum, HashAlgorithm.csum16);
    }
}

V1Switch<headers, metadata>(ParserImpl(), verifyChecksum(), ingress(), egress(), computeChecksum(), DeparserImpl()) main;

void copy_field_list(in metadata from, inout metadata to, in standard_metadata_t smfrom, inout standard_metadata_t smto, in bit<16> discriminator) {
    ;
}
