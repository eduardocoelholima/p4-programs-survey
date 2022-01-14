enum flow_def_t2_0__action_type_t {
    validate_h2,
    drop_4,
    NoAction_4
}

struct flow_def_t2_0 {
    bool                         hit;
    bool                         reach;
    flow_def_t2_0__action_type_t action_run;
    bit<16>                      validate_h2__value;
    @matchKind("exact") 
    bit<16>                      key_t2_0_hdr_h0_value;
}

@controlled() extern flow_def_t2_0 query_t2_0(@matchKind("exact") in bit<16> t2_0_hdr_h0_value);
extern void end_t2_0();
enum flow_def_t1_0__action_type_t {
    validate_h1,
    drop_1,
    NoAction_0
}

struct flow_def_t1_0 {
    bool                         hit;
    bool                         reach;
    flow_def_t1_0__action_type_t action_run;
    bit<16>                      validate_h1__value;
    @matchKind("exact") 
    bit<16>                      key_t1_0_hdr_h0_value;
}

@controlled() extern flow_def_t1_0 query_t1_0(@matchKind("exact") in bit<16> t1_0_hdr_h0_value);
extern void end_t1_0();
enum flow_def_t3_0__action_type_t {
    validate_h3,
    drop_5,
    NoAction_5
}

struct flow_def_t3_0 {
    bool                         hit;
    bool                         reach;
    flow_def_t3_0__action_type_t action_run;
    bit<16>                      validate_h3__value;
    @matchKind("exact") 
    bit<16>                      key_t3_0_hdr_h0_value;
}

@controlled() extern flow_def_t3_0 query_t3_0(@matchKind("exact") in bit<16> t3_0_hdr_h0_value);
extern void end_t3_0();
extern void key_match(in bool condition);
extern void angelic_assert(in bool condition);
extern void bug();

#include <core.p4>

#include <v1model.p4>

struct ghost_t {
    bit<1> used;
}

header h_t {
    bit<16> value;
}

struct metadata {
    bit<1> _ghost_used0;
}

struct headers {
    h_t h0;
    h_t h1;
    h_t h2;
    h_t h3;
    h_t h4;
}

parser ParserImpl(packet_in packet, out headers hdr, inout metadata meta, inout standard_metadata_t standard_metadata) {
    @name(".start") state start {
        packet.extract<h_t>(hdr.h0);
        transition accept;
    }
}

control ingress(inout headers hdr, inout metadata meta, inout standard_metadata_t standard_metadata) {
    bool __track_egress_spec_0;
    apply {
        meta._ghost_used0 = 1w0;
        hdr.h1.setInvalid();
        hdr.h2.setInvalid();
        hdr.h3.setInvalid();
        hdr.h4.setInvalid();
        {
            flow_def_t1_0 t1;
            t1 = query_t1_0(hdr.h0.value);
            if (t1.hit) {
                key_match(hdr.h0.value == t1.key_t1_0_hdr_h0_value);
                if (!hdr.h0.isValid())  {
                    bug();
                } 
            }
            if (t1.action_run == flow_def_t1_0__action_type_t.NoAction_0) {
            }
            else  {
                if (t1.action_run == flow_def_t1_0__action_type_t.drop_1) {
                    angelic_assert(true);
                    {
                    }
                }
                else  {
                    if (t1.action_run == flow_def_t1_0__action_type_t.validate_h1) {
                        angelic_assert(true);
                        {
                            hdr.h1.setValid();
                            if (hdr.h1.isValid())  {
                                hdr.h1.value = t1.validate_h1__value;
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
            end_t1_0();
        }
        {
            flow_def_t2_0 t2;
            t2 = query_t2_0(hdr.h0.value);
            if (t2.hit) {
                key_match(hdr.h0.value == t2.key_t2_0_hdr_h0_value);
                if (!hdr.h0.isValid())  {
                    bug();
                } 
            }
            if (t2.action_run == flow_def_t2_0__action_type_t.NoAction_4) {
            }
            else  {
                if (t2.action_run == flow_def_t2_0__action_type_t.drop_4) {
                    angelic_assert(true);
                    {
                    }
                }
                else  {
                    if (t2.action_run == flow_def_t2_0__action_type_t.validate_h2) {
                        angelic_assert(true);
                        {
                            if (hdr.h2.isValid())  {
                                hdr.h2.value = t2.validate_h2__value;
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
            end_t2_0();
        }
        {
            flow_def_t3_0 t3;
            t3 = query_t3_0(hdr.h0.value);
            if (t3.hit) {
                key_match(hdr.h0.value == t3.key_t3_0_hdr_h0_value);
                if (!hdr.h0.isValid())  {
                    bug();
                } 
            }
            if (t3.action_run == flow_def_t3_0__action_type_t.NoAction_5) {
            }
            else  {
                if (t3.action_run == flow_def_t3_0__action_type_t.drop_5) {
                    angelic_assert(true);
                    {
                    }
                }
                else  {
                    if (t3.action_run == flow_def_t3_0__action_type_t.validate_h3) {
                        angelic_assert(true);
                        {
                            hdr.h3.setValid();
                            if (hdr.h3.isValid())  {
                                hdr.h3.value = t3.validate_h3__value;
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
            end_t3_0();
        }
        standard_metadata.egress_spec = 9w511;
        __track_egress_spec_0 = true;
        if (!__track_egress_spec_0)  {
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
