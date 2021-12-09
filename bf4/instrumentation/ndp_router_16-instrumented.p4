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

struct meta_t {
    bit<16> register_tmp;
    bit<16> ndpflags;
}

struct routing_metadata_t {
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

header ndp_t {
    bit<16> flags;
    bit<16> checksum;
    bit<32> sport;
    bit<32> dport;
    bit<32> seqpull;
    bit<32> pacerecho;
}

struct metadata {
    bit<16> _meta_register_tmp0;
    bit<16> _meta_ndpflags1;
    bit<32> _routing_metadata_nhop_ipv42;
}

struct headers {
    @name(".ethernet") 
    ethernet_t ethernet;
    @name(".ipv4") 
    ipv4_t     ipv4;
    @name(".ndp") 
    ndp_t      ndp;
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
            8w199: parse_ndp;
            default: accept;
        }
    }
    @name(".parse_ndp") state parse_ndp {
        packet.extract<ndp_t>(hdr.ndp);
        transition accept;
    }
    @name(".start") state start {
        transition parse_ethernet;
    }
}

control egress(inout headers hdr, inout metadata meta, inout standard_metadata_t standard_metadata) {
    @name(".NoAction") action NoAction_0() {
    }
    @name(".NoAction") action NoAction_1() {
    }
    @name(".buffersense") register<bit<16>>(32w4) buffersense;
    @name(".decreasereg") action decreasereg() {
        {
            if (!((bit<32>)standard_metadata.egress_port < 32w4))  {
                bug();
            } 
            buffersense.read(meta._meta_register_tmp0, (bit<32>)standard_metadata.egress_port);
        }
        {
            if (!((bit<32>)standard_metadata.egress_port < 32w4))  {
                bug();
            } 
            buffersense.write((bit<32>)standard_metadata.egress_port, meta._meta_register_tmp0 + 16w65535 + (bit<16>)standard_metadata.egress_spec);
        }
    }
    @name(".cont") action cont() {
    }
    @name(".rewrite_mac") action rewrite_mac(bit<48> smac) {
        {
            if (hdr.ethernet.isValid())  {
                hdr.ethernet.srcAddr = smac;
            } 
            else  {
                bug();
            }
        }
    }
    @name("._drop") action _drop() {
        standard_metadata.egress_spec = 9w511;
    }
    @name(".dec_counter") @instrument_keys() table dec_counter {
        actions = {
            decreasereg();
            cont();
            @defaultonly NoAction_0();
        }
        key = {
            meta._meta_ndpflags1: range @name("meta.ndpflags") ;
        }
        size = 2;
        default_action = NoAction_0();
    }
    @name(".send_frame") @instrument_keys() table send_frame {
        actions = {
            rewrite_mac();
            _drop();
            @defaultonly NoAction_1();
        }
        key = {
            standard_metadata.egress_port: exact @name("standard_metadata.egress_port") ;
        }
        size = 256;
        default_action = NoAction_1();
    }
    apply {
        dec_counter.apply();
        send_frame.apply();
    }
}

control ingress(inout headers hdr, inout metadata meta, inout standard_metadata_t standard_metadata) {
    bool __track_egress_spec;
    @name(".NoAction") action NoAction_9() {
    }
    @name(".NoAction") action NoAction_10() {
    }
    @name(".NoAction") action NoAction_11() {
    }
    @name(".NoAction") action NoAction_12() {
    }
    @name(".NoAction") action NoAction_13() {
    }
    @name(".buffersense") register<bit<16>>(32w4) buffersense_2;
    @name(".directpriohigh") action directpriohigh() {
        {
            standard_metadata.egress_spec = 9w1;
            __track_egress_spec = true;
        }
        {
            if (hdr.ndp.isValid())  {
                meta._meta_ndpflags1 = hdr.ndp.flags;
            } 
            else  {
                bug();
            }
        }
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
        {
            if (!((bit<32>)standard_metadata.egress_port < 32w4))  {
                bug();
            } 
            buffersense_2.read(meta._meta_register_tmp0, (bit<32>)standard_metadata.egress_port);
        }
    }
    @name("._drop") action _drop_2() {
        {
            standard_metadata.egress_spec = 9w511;
            __track_egress_spec = true;
        }
    }
    @name("._drop") action _drop_4() {
        {
            standard_metadata.egress_spec = 9w511;
            __track_egress_spec = true;
        }
    }
    @name(".set_nhop") action set_nhop(bit<32> nhop_ipv4, bit<9> port) {
        meta._routing_metadata_nhop_ipv42 = nhop_ipv4;
        standard_metadata.egress_port = port;
        {
            if (hdr.ipv4.isValid() && hdr.ipv4.isValid())  {
                hdr.ipv4.ttl = hdr.ipv4.ttl + 8w255;
            } 
            else  {
                bug();
            }
        }
    }
    @name(".readbuffer") action readbuffer() {
        {
            if (!((bit<32>)standard_metadata.egress_port < 32w4))  {
                bug();
            } 
            buffersense_2.read(meta._meta_register_tmp0, (bit<32>)standard_metadata.egress_port);
        }
    }
    @name(".setpriolow") action setpriolow() {
        {
            standard_metadata.egress_spec = 9w0;
            __track_egress_spec = true;
        }
        {
            if (!((bit<32>)standard_metadata.egress_port < 32w4))  {
                bug();
            } 
            buffersense_2.read(meta._meta_register_tmp0, (bit<32>)standard_metadata.egress_port);
        }
        {
            if (!((bit<32>)standard_metadata.egress_port < 32w4))  {
                bug();
            } 
            buffersense_2.write((bit<32>)standard_metadata.egress_port, meta._meta_register_tmp0 + 16w1);
        }
    }
    @name(".setpriohigh") action setpriohigh() {
        truncate(32w54);
        {
            if (hdr.ipv4.isValid())  {
                hdr.ipv4.totalLen = 16w20;
            } 
            else  {
                bug();
            }
        }
        {
            standard_metadata.egress_spec = 9w1;
            __track_egress_spec = true;
        }
    }
    @name(".directtoprio") @instrument_keys() table directtoprio {
        actions = {
            directpriohigh();
            @defaultonly NoAction_9();
        }
        key = {
            meta._meta_register_tmp0: range @name("meta.register_tmp") ;
        }
        size = 2;
        default_action = NoAction_9();
    }
    @name(".forward") @instrument_keys() table forward {
        actions = {
            set_dmac();
            _drop_2();
            @defaultonly NoAction_10();
        }
        key = {
            meta._routing_metadata_nhop_ipv42: exact @name("routing_metadata.nhop_ipv4") ;
        }
        size = 512;
        default_action = NoAction_10();
    }
    @name(".ipv4_lpm") @instrument_keys() table ipv4_lpm {
        actions = {
            set_nhop();
            _drop_4();
            @defaultonly NoAction_11();
        }
        key = {
            hdr.ipv4.dstAddr: lpm @name("ipv4.dstAddr") ;
        }
        size = 1024;
        default_action = NoAction_11();
    }
    @name(".readbuffersense") @instrument_keys() table readbuffersense {
        actions = {
            readbuffer();
            @defaultonly NoAction_12();
        }
        key = {
            meta._meta_register_tmp0: range @name("meta.register_tmp") ;
        }
        size = 2;
        default_action = NoAction_12();
    }
    @name(".setprio") @instrument_keys() table setprio {
        actions = {
            setpriolow();
            setpriohigh();
            @defaultonly NoAction_13();
        }
        key = {
            meta._meta_register_tmp0: range @name("meta.register_tmp") ;
        }
        size = 2;
        default_action = NoAction_13();
    }
    apply {
        __track_egress_spec = false;
        if (hdr.ipv4.isValid() || !hdr.ipv4.isValid())  {
            if (hdr.ipv4.isValid() && hdr.ipv4.ttl > 8w0) {
                ipv4_lpm.apply();
                if (hdr.ndp.isValid() || !hdr.ndp.isValid())  {
                    if (hdr.ndp.isValid() && hdr.ndp.flags > 16w1)  {
                        directtoprio.apply();
                    } 
                    else {
                        readbuffersense.apply();
                        setprio.apply();
                    }
                } 
                else  {
                    bug();
                }
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
        packet.emit<ethernet_t>(hdr.ethernet);
        packet.emit<ipv4_t>(hdr.ipv4);
        packet.emit<ndp_t>(hdr.ndp);
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
