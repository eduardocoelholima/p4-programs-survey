enum flow_def_forward_0__action_type_t {
    set_dmac,
    _drop_2,
    NoAction_10
}

struct flow_def_forward_0 {
    bool                              hit;
    bool                              reach;
    flow_def_forward_0__action_type_t action_run;
    bit<48>                           set_dmac__dmac;
    @matchKind("exact") 
    bit<32>                           key_forward_0_routing_metadata_nhop_ipv4;
}

@controlled() extern flow_def_forward_0 query_forward_0(@matchKind("exact") in bit<32> forward_0_routing_metadata_nhop_ipv4);
extern void end_forward_0();
enum flow_def_directtoprio_0__action_type_t {
    directpriohigh,
    NoAction_9
}

struct flow_def_directtoprio_0 {
    bool                                   hit;
    bool                                   reach;
    flow_def_directtoprio_0__action_type_t action_run;
    @matchKind("range") 
    bit<16>                                key_directtoprio_0_meta_register_tmp__min;
    @matchKind("range") 
    bit<16>                                key_directtoprio_0_meta_register_tmp__max;
}

@controlled() extern flow_def_directtoprio_0 query_directtoprio_0(@matchKind("range") in bit<16> directtoprio_0_meta_register_tmp);
extern void end_directtoprio_0();
enum flow_def_send_frame_0__action_type_t {
    rewrite_mac,
    _drop,
    NoAction_1
}

struct flow_def_send_frame_0 {
    bool                                 hit;
    bool                                 reach;
    flow_def_send_frame_0__action_type_t action_run;
    bit<48>                              rewrite_mac__smac;
    @matchKind("exact") 
    bit<9>                               key_send_frame_0_standard_metadata_egress_port;
}

@controlled() extern flow_def_send_frame_0 query_send_frame_0(@matchKind("exact") in bit<9> send_frame_0_standard_metadata_egress_port);
extern void end_send_frame_0();
enum flow_def_dec_counter_0__action_type_t {
    decreasereg,
    cont,
    NoAction_0
}

struct flow_def_dec_counter_0 {
    bool                                  hit;
    bool                                  reach;
    flow_def_dec_counter_0__action_type_t action_run;
    @matchKind("range") 
    bit<16>                               key_dec_counter_0_meta_ndpflags__min;
    @matchKind("range") 
    bit<16>                               key_dec_counter_0_meta_ndpflags__max;
}

@controlled() extern flow_def_dec_counter_0 query_dec_counter_0(@matchKind("range") in bit<16> dec_counter_0_meta_ndpflags);
extern void end_dec_counter_0();
enum flow_def_setprio_0__action_type_t {
    setpriolow,
    setpriohigh,
    NoAction_13
}

struct flow_def_setprio_0 {
    bool                              hit;
    bool                              reach;
    flow_def_setprio_0__action_type_t action_run;
    @matchKind("range") 
    bit<16>                           key_setprio_0_meta_register_tmp__min;
    @matchKind("range") 
    bit<16>                           key_setprio_0_meta_register_tmp__max;
}

@controlled() extern flow_def_setprio_0 query_setprio_0(@matchKind("range") in bit<16> setprio_0_meta_register_tmp);
extern void end_setprio_0();
enum flow_def_readbuffersense_0__action_type_t {
    readbuffer,
    NoAction_12
}

struct flow_def_readbuffersense_0 {
    bool                                      hit;
    bool                                      reach;
    flow_def_readbuffersense_0__action_type_t action_run;
    @matchKind("range") 
    bit<16>                                   key_readbuffersense_0_meta_register_tmp__min;
    @matchKind("range") 
    bit<16>                                   key_readbuffersense_0_meta_register_tmp__max;
}

@controlled() extern flow_def_readbuffersense_0 query_readbuffersense_0(@matchKind("range") in bit<16> readbuffersense_0_meta_register_tmp);
extern void end_readbuffersense_0();
enum flow_def_ipv4_lpm_0__action_type_t {
    set_nhop,
    _drop_4,
    NoAction_11
}

struct flow_def_ipv4_lpm_0 {
    bool                               hit;
    bool                               reach;
    flow_def_ipv4_lpm_0__action_type_t action_run;
    bit<32>                            set_nhop__nhop_ipv4;
    bit<9>                             set_nhop__port;
    @matchKind("lpm") 
    bit<32>                            key_ipv4_lpm_0_ipv4_dstAddr__val;
    @matchKind("lpm") 
    bit<32>                            key_ipv4_lpm_0_ipv4_dstAddr__prefix;
}

@controlled() extern flow_def_ipv4_lpm_0 query_ipv4_lpm_0(@matchKind("lpm") in bit<32> ipv4_lpm_0_ipv4_dstAddr);
extern void end_ipv4_lpm_0();
extern void key_match(in bool condition);
extern void angelic_assert(in bool condition);
extern void bug();

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
    @name(".buffersense") register<bit<16>>(32w4) buffersense_0;
    apply {
        {
            flow_def_dec_counter_0 dec_counter;
            dec_counter = query_dec_counter_0(meta._meta_ndpflags1);
            if (dec_counter.hit) {
                key_match(meta._meta_ndpflags1 <= dec_counter.key_dec_counter_0_meta_ndpflags__max && meta._meta_ndpflags1 >= dec_counter.key_dec_counter_0_meta_ndpflags__min);
            }
            if (dec_counter.action_run == flow_def_dec_counter_0__action_type_t.NoAction_0) {
            }
            else  {
                if (dec_counter.action_run == flow_def_dec_counter_0__action_type_t.cont) {
                    angelic_assert(true);
                    {
                    }
                }
                else  {
                    if (dec_counter.action_run == flow_def_dec_counter_0__action_type_t.decreasereg) {
                        angelic_assert(true);
                        {
                            if ((bit<32>)standard_metadata.egress_port >= 32w4)  {
                                bug();
                            } 
                            buffersense_0.read(meta._meta_register_tmp0, (bit<32>)standard_metadata.egress_port);
                            if ((bit<32>)standard_metadata.egress_port >= 32w4)  {
                                bug();
                            } 
                            buffersense_0.write((bit<32>)standard_metadata.egress_port, meta._meta_register_tmp0 + 16w65535 + (bit<16>)standard_metadata.egress_spec);
                        }
                    }
                    else  {
                        ;
                    }
                }
            }
            end_dec_counter_0();
        }
        {
            flow_def_send_frame_0 send_frame;
            send_frame = query_send_frame_0(standard_metadata.egress_port);
            if (send_frame.hit) {
                key_match(standard_metadata.egress_port == send_frame.key_send_frame_0_standard_metadata_egress_port);
            }
            if (send_frame.action_run == flow_def_send_frame_0__action_type_t.NoAction_1) {
            }
            else  {
                if (send_frame.action_run == flow_def_send_frame_0__action_type_t._drop) {
                    angelic_assert(true);
                    {
                        standard_metadata.egress_spec = 9w511;
                    }
                }
                else  {
                    if (send_frame.action_run == flow_def_send_frame_0__action_type_t.rewrite_mac) {
                        angelic_assert(true);
                        {
                            if (hdr.ethernet.isValid())  {
                                hdr.ethernet.srcAddr = send_frame.rewrite_mac__smac;
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
    }
}

control ingress(inout headers hdr, inout metadata meta, inout standard_metadata_t standard_metadata) {
    bool __track_egress_spec_0;
    @name(".buffersense") register<bit<16>>(32w4) buffersense_1;
    apply {
        __track_egress_spec_0 = false;
        if (hdr.ipv4.isValid() || !hdr.ipv4.isValid())  {
            if (hdr.ipv4.isValid() && hdr.ipv4.ttl > 8w0) {
                {
                    flow_def_ipv4_lpm_0 ipv4_lpm;
                    ipv4_lpm = query_ipv4_lpm_0(hdr.ipv4.dstAddr);
                    if (ipv4_lpm.hit) {
                        key_match(hdr.ipv4.dstAddr & (32w1 << ipv4_lpm.key_ipv4_lpm_0_ipv4_dstAddr__prefix) - 32w1 == ipv4_lpm.key_ipv4_lpm_0_ipv4_dstAddr__val & (32w1 << ipv4_lpm.key_ipv4_lpm_0_ipv4_dstAddr__prefix) - 32w1);
                        if (!(hdr.ipv4.isValid() || (32w1 << ipv4_lpm.key_ipv4_lpm_0_ipv4_dstAddr__prefix) - 32w1 == 32w0))  {
                            bug();
                        } 
                    }
                    if (ipv4_lpm.action_run == flow_def_ipv4_lpm_0__action_type_t.NoAction_11) {
                    }
                    else  {
                        if (ipv4_lpm.action_run == flow_def_ipv4_lpm_0__action_type_t._drop_4) {
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
                                    meta._routing_metadata_nhop_ipv42 = ipv4_lpm.set_nhop__nhop_ipv4;
                                    standard_metadata.egress_port = ipv4_lpm.set_nhop__port;
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
                if (hdr.ndp.isValid() || !hdr.ndp.isValid())  {
                    if (hdr.ndp.isValid() && hdr.ndp.flags > 16w1) {
                        flow_def_directtoprio_0 directtoprio;
                        directtoprio = query_directtoprio_0(meta._meta_register_tmp0);
                        if (directtoprio.hit) {
                            key_match(meta._meta_register_tmp0 <= directtoprio.key_directtoprio_0_meta_register_tmp__max && meta._meta_register_tmp0 >= directtoprio.key_directtoprio_0_meta_register_tmp__min);
                        }
                        if (directtoprio.action_run == flow_def_directtoprio_0__action_type_t.NoAction_9) {
                        }
                        else  {
                            if (directtoprio.action_run == flow_def_directtoprio_0__action_type_t.directpriohigh) {
                                angelic_assert(true);
                                {
                                    standard_metadata.egress_spec = 9w1;
                                    __track_egress_spec_0 = true;
                                    if (hdr.ndp.isValid())  {
                                        meta._meta_ndpflags1 = hdr.ndp.flags;
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
                        end_directtoprio_0();
                    }
                    else {
                        {
                            flow_def_readbuffersense_0 readbuffersense;
                            readbuffersense = query_readbuffersense_0(meta._meta_register_tmp0);
                            if (readbuffersense.hit) {
                                key_match(meta._meta_register_tmp0 <= readbuffersense.key_readbuffersense_0_meta_register_tmp__max && meta._meta_register_tmp0 >= readbuffersense.key_readbuffersense_0_meta_register_tmp__min);
                            }
                            if (readbuffersense.action_run == flow_def_readbuffersense_0__action_type_t.NoAction_12) {
                            }
                            else  {
                                if (readbuffersense.action_run == flow_def_readbuffersense_0__action_type_t.readbuffer) {
                                    angelic_assert(true);
                                    {
                                        if ((bit<32>)standard_metadata.egress_port >= 32w4)  {
                                            bug();
                                        } 
                                        buffersense_1.read(meta._meta_register_tmp0, (bit<32>)standard_metadata.egress_port);
                                    }
                                }
                                else  {
                                    ;
                                }
                            }
                            end_readbuffersense_0();
                        }
                        {
                            flow_def_setprio_0 setprio;
                            setprio = query_setprio_0(meta._meta_register_tmp0);
                            if (setprio.hit) {
                                key_match(meta._meta_register_tmp0 <= setprio.key_setprio_0_meta_register_tmp__max && meta._meta_register_tmp0 >= setprio.key_setprio_0_meta_register_tmp__min);
                            }
                            if (setprio.action_run == flow_def_setprio_0__action_type_t.NoAction_13) {
                            }
                            else  {
                                if (setprio.action_run == flow_def_setprio_0__action_type_t.setpriohigh) {
                                    angelic_assert(true);
                                    {
                                        truncate(32w54);
                                        if (hdr.ipv4.isValid())  {
                                            hdr.ipv4.totalLen = 16w20;
                                        } 
                                        else  {
                                            bug();
                                        }
                                        standard_metadata.egress_spec = 9w1;
                                        __track_egress_spec_0 = true;
                                    }
                                }
                                else  {
                                    if (setprio.action_run == flow_def_setprio_0__action_type_t.setpriolow) {
                                        angelic_assert(true);
                                        {
                                            standard_metadata.egress_spec = 9w0;
                                            __track_egress_spec_0 = true;
                                            if ((bit<32>)standard_metadata.egress_port >= 32w4)  {
                                                bug();
                                            } 
                                            buffersense_1.read(meta._meta_register_tmp0, (bit<32>)standard_metadata.egress_port);
                                            if ((bit<32>)standard_metadata.egress_port >= 32w4)  {
                                                bug();
                                            } 
                                            buffersense_1.write((bit<32>)standard_metadata.egress_port, meta._meta_register_tmp0 + 16w1);
                                        }
                                    }
                                    else  {
                                        ;
                                    }
                                }
                            }
                            end_setprio_0();
                        }
                    }
                } 
                else  {
                    bug();
                }
                {
                    flow_def_forward_0 forward;
                    forward = query_forward_0(meta._routing_metadata_nhop_ipv42);
                    if (forward.hit) {
                        key_match(meta._routing_metadata_nhop_ipv42 == forward.key_forward_0_routing_metadata_nhop_ipv4);
                    }
                    if (forward.action_run == flow_def_forward_0__action_type_t.NoAction_10) {
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
                                    if ((bit<32>)standard_metadata.egress_port >= 32w4)  {
                                        bug();
                                    } 
                                    buffersense_1.read(meta._meta_register_tmp0, (bit<32>)standard_metadata.egress_port);
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
