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

struct local_metadata_t {
    bit<16> proposal;
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
    bit<32> src;
    bit<32> dst;
}

header paxos_t {
    bit<32> inst;
    bit<16> proposal;
    bit<16> vproposal;
    bit<16> acpt;
    bit<16> msgtype;
    bit<32> val;
    bit<32> fsh;
    bit<32> fsl;
    bit<32> feh;
    bit<32> fel;
    bit<32> csh;
    bit<32> csl;
    bit<32> ceh;
    bit<32> cel;
    bit<32> ash;
    bit<32> asl;
    bit<32> aeh;
    bit<32> ael;
}

header udp_t {
    bit<16> srcPort;
    bit<16> dstPort;
    bit<16> length_;
    bit<16> checksum;
}

struct metadata {
    bit<16> _local_metadata_proposal0;
}

struct headers {
    @name(".ethernet") 
    ethernet_t ethernet;
    @name(".ipv4") 
    ipv4_t     ipv4;
    @name(".paxos") 
    paxos_t    paxos;
    @name(".udp") 
    udp_t      udp;
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
            8w0x11: parse_udp;
            default: accept;
        }
    }
    @name(".parse_paxos") state parse_paxos {
        packet.extract<paxos_t>(hdr.paxos);
        transition accept;
    }
    @name(".parse_udp") state parse_udp {
        packet.extract<udp_t>(hdr.udp);
        transition select(hdr.udp.dstPort) {
            16w0x8888: parse_paxos;
            default: accept;
        }
    }
    @name(".start") state start {
        transition parse_ethernet;
    }
}

control ingress(inout headers hdr, inout metadata meta, inout standard_metadata_t standard_metadata) {
    bool __track_egress_spec;
    @name(".NoAction") action NoAction_0() {
    }
    @name(".NoAction") action NoAction_5() {
    }
    @name(".NoAction") action NoAction_6() {
    }
    @name(".NoAction") action NoAction_7() {
    }
    @name(".acceptor_id") register<bit<16>>(32w1) acceptor_id;
    @name(".proposal_register") register<bit<16>>(32w64000) proposal_register;
    @name(".val_register") register<bit<32>>(32w64000) val_register;
    @name(".vproposal_register") register<bit<16>>(32w64000) vproposal_register;
    @name("._drop") action _drop() {
        {
            standard_metadata.egress_spec = 9w511;
            __track_egress_spec = true;
        }
    }
    @name("._drop") action _drop_2() {
        {
            standard_metadata.egress_spec = 9w511;
            __track_egress_spec = true;
        }
    }
    @name("._no_op") action _no_op() {
    }
    @name(".forward") action forward(bit<9> port) {
        {
            standard_metadata.egress_spec = port;
            __track_egress_spec = true;
        }
    }
    @name(".handle_phase1a") action handle_phase1a() {
        if (hdr.paxos.isValid() && hdr.paxos.isValid()) {
            if (!(hdr.paxos.inst < 32w64000))  {
                bug();
            } 
            proposal_register.write(hdr.paxos.inst, hdr.paxos.proposal);
        }
        else  {
            bug();
        }
        if (hdr.paxos.isValid()) {
            if (!(hdr.paxos.inst < 32w64000))  {
                bug();
            } 
            vproposal_register.read(hdr.paxos.vproposal, hdr.paxos.inst);
        }
        else  {
            bug();
        }
        if (hdr.paxos.isValid()) {
            if (!(hdr.paxos.inst < 32w64000))  {
                bug();
            } 
            val_register.read(hdr.paxos.val, hdr.paxos.inst);
        }
        else  {
            bug();
        }
        {
            if (hdr.paxos.isValid())  {
                hdr.paxos.msgtype = 16w2;
            } 
            else  {
                bug();
            }
        }
        {
            if (!(32w0 < 32w1))  {
                bug();
            } 
            acceptor_id.read(hdr.paxos.acpt, 32w0);
        }
        {
            if (hdr.udp.isValid())  {
                hdr.udp.checksum = 16w0;
            } 
            else  {
                bug();
            }
        }
    }
    @name(".handle_phase2a") action handle_phase2a() {
        if (hdr.paxos.isValid() && hdr.paxos.isValid()) {
            if (!(hdr.paxos.inst < 32w64000))  {
                bug();
            } 
            proposal_register.write(hdr.paxos.inst, hdr.paxos.proposal);
        }
        else  {
            bug();
        }
        if (hdr.paxos.isValid() && hdr.paxos.isValid()) {
            if (!(hdr.paxos.inst < 32w64000))  {
                bug();
            } 
            vproposal_register.write(hdr.paxos.inst, hdr.paxos.proposal);
        }
        else  {
            bug();
        }
        if (hdr.paxos.isValid() && hdr.paxos.isValid()) {
            if (!(hdr.paxos.inst < 32w64000))  {
                bug();
            } 
            val_register.write(hdr.paxos.inst, hdr.paxos.val);
        }
        else  {
            bug();
        }
        {
            if (hdr.paxos.isValid())  {
                hdr.paxos.msgtype = 16w4;
            } 
            else  {
                bug();
            }
        }
        {
            if (hdr.paxos.isValid() && hdr.paxos.isValid())  {
                hdr.paxos.vproposal = hdr.paxos.proposal;
            } 
            else  {
                bug();
            }
        }
        {
            if (!(32w0 < 32w1))  {
                bug();
            } 
            acceptor_id.read(hdr.paxos.acpt, 32w0);
        }
        {
            if (hdr.udp.isValid())  {
                hdr.udp.checksum = 16w0;
            } 
            else  {
                bug();
            }
        }
    }
    @name(".read_round") action read_round() {
        if (hdr.paxos.isValid()) {
            if (!(hdr.paxos.inst < 32w64000))  {
                bug();
            } 
            proposal_register.read(meta._local_metadata_proposal0, hdr.paxos.inst);
        }
        else  {
            bug();
        }
    }
    @name(".drop_tbl") @instrument_keys() table drop_tbl {
        actions = {
            _drop();
            @defaultonly NoAction_0();
        }
        size = 1;
        default_action = NoAction_0();
    }
    @name(".fwd_tbl") @instrument_keys() table fwd_tbl {
        actions = {
            forward();
            _drop_2();
            @defaultonly NoAction_5();
        }
        key = {
            standard_metadata.ingress_port: exact @name("standard_metadata.ingress_port") ;
        }
        size = 8;
        default_action = NoAction_5();
    }
    @name(".paxos_tbl") @instrument_keys() table paxos_tbl {
        actions = {
            handle_phase1a();
            handle_phase2a();
            _no_op();
            @defaultonly NoAction_6();
        }
        key = {
            hdr.paxos.msgtype: exact @name("paxos.msgtype") ;
        }
        size = 8;
        default_action = NoAction_6();
    }
    @name(".round_tbl") @instrument_keys() table round_tbl {
        actions = {
            read_round();
            @defaultonly NoAction_7();
        }
        size = 1;
        default_action = NoAction_7();
    }
    apply {
        __track_egress_spec = false;
        if (hdr.ipv4.isValid())  {
            fwd_tbl.apply();
        } 
        if (hdr.paxos.isValid()) {
            round_tbl.apply();
            if (hdr.paxos.isValid())  {
                if (meta._local_metadata_proposal0 <= hdr.paxos.proposal)  {
                    paxos_tbl.apply();
                } 
                else  {
                    drop_tbl.apply();
                }
            } 
            else  {
                bug();
            }
        }
        if (!__track_egress_spec)  {
            bug();
        } 
    }
}

control egress(inout headers hdr, inout metadata meta, inout standard_metadata_t standard_metadata) {
    apply {
    }
}

control DeparserImpl(packet_out packet, in headers hdr) {
    apply {
        packet.emit<ethernet_t>(hdr.ethernet);
        packet.emit<ipv4_t>(hdr.ipv4);
        packet.emit<udp_t>(hdr.udp);
        packet.emit<paxos_t>(hdr.paxos);
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
