extern H havoc<H>();
extern void key_match(in bool condition);
extern void assert(in bool condition);
extern void angelic_assert(in bool condition);
extern void assume(in bool condition);
extern void bug();
extern void oob();
extern void dontCare();
extern void do_drop();

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
    bit<64> tmp_0;
    @name(".parse_cpu_header") state parse_cpu_header {
        packet.extract<cpu_header_t>(hdr.cpu_header);
        {
            if (hdr.cpu_header.isValid())  {
                meta._meta_if_index10 = hdr.cpu_header.if_index;
            } 
            else  {
                bug();
            }
        }
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
        {
            if (hdr.ipv4.isValid())  {
                meta._meta_ipv4_sa1 = hdr.ipv4.srcAddr;
            } 
            else  {
                bug();
            }
        }
        {
            if (hdr.ipv4.isValid())  {
                meta._meta_ipv4_da2 = hdr.ipv4.dstAddr;
            } 
            else  {
                bug();
            }
        }
        {
            if (hdr.ipv4.isValid())  {
                meta._meta_tcpLength9 = hdr.ipv4.totalLen + 16w65516;
            } 
            else  {
                bug();
            }
        }
        transition select(hdr.ipv4.protocol) {
            8w0x6: parse_tcp;
            default: accept;
        }
    }
    @name(".parse_tcp") state parse_tcp {
        packet.extract<tcp_t>(hdr.tcp);
        {
            if (hdr.tcp.isValid())  {
                meta._meta_tcp_sp3 = hdr.tcp.srcPort;
            } 
            else  {
                bug();
            }
        }
        {
            if (hdr.tcp.isValid())  {
                meta._meta_tcp_dp4 = hdr.tcp.dstPort;
            } 
            else  {
                bug();
            }
        }
        transition accept;
    }
    @name(".start") state start {
        meta._meta_if_index10 = (bit<8>)standard_metadata.ingress_port;
        tmp_0 = packet.lookahead<bit<64>>();
        tmp = tmp_0;
        transition select(tmp[63:0]) {
            64w0: parse_cpu_header;
            default: parse_ethernet;
        }
    }
}

control egress(inout headers hdr, inout metadata meta, inout standard_metadata_t standard_metadata) {
    @name(".NoAction") action NoAction_0() {
    }
    @name(".NoAction") action NoAction_1() {
    }
    @name(".do_rewrites") action do_rewrites(bit<48> smac) {
        hdr.cpu_header.setInvalid();
        {
            if (hdr.ethernet.isValid())  {
                hdr.ethernet.srcAddr = smac;
            } 
            else  {
                bug();
            }
        }
        {
            if (hdr.ipv4.isValid())  {
                hdr.ipv4.srcAddr = meta._meta_ipv4_sa1;
            } 
            else  {
                bug();
            }
        }
        {
            if (hdr.ipv4.isValid())  {
                hdr.ipv4.dstAddr = meta._meta_ipv4_da2;
            } 
            else  {
                bug();
            }
        }
        {
            if (hdr.tcp.isValid())  {
                hdr.tcp.srcPort = meta._meta_tcp_sp3;
            } 
            else  {
                bug();
            }
        }
        {
            if (hdr.tcp.isValid())  {
                hdr.tcp.dstPort = meta._meta_tcp_dp4;
            } 
            else  {
                bug();
            }
        }
    }
    @name("._drop") action _drop() {
        standard_metadata.egress_spec = 9w511;
    }
    @name(".do_cpu_encap") action do_cpu_encap() {
        hdr.cpu_header.setValid();
        {
            if (hdr.cpu_header.isValid())  {
                hdr.cpu_header.preamble = 64w0;
            } 
            else  {
                bug();
            }
        }
        {
            if (hdr.cpu_header.isValid())  {
                hdr.cpu_header.device = 8w0;
            } 
            else  {
                bug();
            }
        }
        {
            if (hdr.cpu_header.isValid())  {
                hdr.cpu_header.reason = 8w0xab;
            } 
            else  {
                bug();
            }
        }
        {
            if (hdr.cpu_header.isValid())  {
                hdr.cpu_header.if_index = meta._meta_if_index10;
            } 
            else  {
                bug();
            }
        }
    }
    @name(".send_frame") @instrument_keys() table send_frame {
        actions = {
            do_rewrites();
            _drop();
            @defaultonly NoAction_0();
        }
        key = {
            standard_metadata.egress_port: exact @name("standard_metadata.egress_port") ;
        }
        size = 256;
        default_action = NoAction_0();
    }
    @name(".send_to_cpu") @instrument_keys() table send_to_cpu {
        actions = {
            do_cpu_encap();
            @defaultonly NoAction_1();
        }
        default_action = NoAction_1();
    }
    apply {
        if (standard_metadata.instance_type == 32w0)  {
            send_frame.apply();
        } 
        else  {
            send_to_cpu.apply();
        }
    }
}

control ingress(inout headers hdr, inout metadata meta, inout standard_metadata_t standard_metadata) {
    bool __track_egress_spec;
    @name(".NoAction") action NoAction_8() {
    }
    @name(".NoAction") action NoAction_9() {
    }
    @name(".NoAction") action NoAction_10() {
    }
    @name(".NoAction") action NoAction_11() {
    }
    @name(".set_dmac") action set_dmac(bit<48> dmac) {
        {
            if (hdr.ethernet.isValid())  {
                hdr.ethernet.dstAddr = dmac;
            } 
            else  {
                bug();
            }
        }
    }
    @name("._drop") action _drop_2() {
        {
            standard_metadata.egress_spec = 9w511;
            __track_egress_spec = true;
        }
    }
    @name("._drop") action _drop_6() {
        {
            standard_metadata.egress_spec = 9w511;
            __track_egress_spec = true;
        }
    }
    @name("._drop") action _drop_7() {
        {
            standard_metadata.egress_spec = 9w511;
            __track_egress_spec = true;
        }
    }
    @name("._drop") action _drop_8() {
        {
            standard_metadata.egress_spec = 9w511;
            __track_egress_spec = true;
        }
    }
    @name(".set_if_info") action set_if_info(bit<32> ipv4_addr, bit<48> mac_addr, bit<1> is_ext) {
        meta._meta_if_ipv4_addr6 = ipv4_addr;
        meta._meta_if_mac_addr7 = mac_addr;
        meta._meta_is_ext_if8 = is_ext;
    }
    @name(".set_nhop") action set_nhop(bit<32> nhop_ipv4, bit<9> port) {
        meta._meta_nhop_ipv45 = nhop_ipv4;
        {
            standard_metadata.egress_spec = port;
            __track_egress_spec = true;
        }
        {
            if (hdr.ipv4.isValid() && hdr.ipv4.isValid())  {
                hdr.ipv4.ttl = hdr.ipv4.ttl + 8w255;
            } 
            else  {
                bug();
            }
        }
    }
    @name(".nat_miss_int_to_ext") action nat_miss_int_to_ext() {
        standard_metadata.clone_spec = 32w65786;
    }
    @name(".nat_miss_ext_to_int") action nat_miss_ext_to_int() {
        meta._meta_do_forward0 = 1w0;
        {
            standard_metadata.egress_spec = 9w511;
            __track_egress_spec = true;
        }
    }
    @name(".nat_hit_int_to_ext") action nat_hit_int_to_ext(bit<32> srcAddr, bit<16> srcPort) {
        meta._meta_do_forward0 = 1w1;
        meta._meta_ipv4_sa1 = srcAddr;
        meta._meta_tcp_sp3 = srcPort;
    }
    @name(".nat_hit_ext_to_int") action nat_hit_ext_to_int(bit<32> dstAddr, bit<16> dstPort) {
        meta._meta_do_forward0 = 1w1;
        meta._meta_ipv4_da2 = dstAddr;
        meta._meta_tcp_dp4 = dstPort;
    }
    @name(".nat_no_nat") action nat_no_nat() {
        meta._meta_do_forward0 = 1w1;
    }
    @name(".forward") @instrument_keys() table forward {
        actions = {
            set_dmac();
            _drop_2();
            @defaultonly NoAction_8();
        }
        key = {
            meta._meta_nhop_ipv45: exact @name("meta.nhop_ipv4") ;
        }
        size = 512;
        default_action = NoAction_8();
    }
    @name(".if_info") @instrument_keys() table if_info {
        actions = {
            _drop_6();
            set_if_info();
            @defaultonly NoAction_9();
        }
        key = {
            meta._meta_if_index10: exact @name("meta.if_index") ;
        }
        default_action = NoAction_9();
    }
    @name(".ipv4_lpm") @instrument_keys() table ipv4_lpm {
        actions = {
            set_nhop();
            _drop_7();
            @defaultonly NoAction_10();
        }
        key = {
            meta._meta_ipv4_da2: lpm @name("meta.ipv4_da") ;
        }
        size = 1024;
        default_action = NoAction_10();
    }
    @name(".nat") @instrument_keys() table nat {
        actions = {
            _drop_8();
            nat_miss_int_to_ext();
            nat_miss_ext_to_int();
            nat_hit_int_to_ext();
            nat_hit_ext_to_int();
            nat_no_nat();
            @defaultonly NoAction_11();
        }
        key = {
            meta._meta_is_ext_if8: exact @name("meta.is_ext_if") ;
            hdr.ipv4.isValid()   : exact @name("ipv4.$valid$") ;
            hdr.tcp.isValid()    : exact @name("tcp.$valid$") ;
            hdr.ipv4.srcAddr     : ternary @name("ipv4.srcAddr") ;
            hdr.ipv4.dstAddr     : ternary @name("ipv4.dstAddr") ;
            hdr.tcp.srcPort      : ternary @name("tcp.srcPort") ;
            hdr.tcp.dstPort      : ternary @name("tcp.dstPort") ;
        }
        size = 128;
        default_action = NoAction_11();
    }
    apply {
        __track_egress_spec = false;
        if_info.apply();
        nat.apply();
        if (hdr.ipv4.isValid() || !(meta._meta_do_forward0 == 1w1))  {
            if (meta._meta_do_forward0 == 1w1 && hdr.ipv4.ttl > 8w0) {
                ipv4_lpm.apply();
                forward.apply();
            }
        } 
        else  {
            bug();
        }
        if (!__track_egress_spec)  {
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
