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
    @name(".NoAction") action NoAction_0() {
    }
    @name(".NoAction") action NoAction_5() {
    }
    @name(".NoAction") action NoAction_6() {
    }
    @name(".NoAction") action NoAction_7() {
    }
    @name("ingress.drop_") action drop_1() {
        standard_metadata.egress_spec = 9w511;
    }
    @name("ingress.drop_") action drop_5() {
        standard_metadata.egress_spec = 9w511;
    }
    @name("ingress.drop_") action drop_6() {
        standard_metadata.egress_spec = 9w511;
    }
    @name("ingress.drop_") action drop_7() {
        standard_metadata.egress_spec = 9w511;
    }
    @name("ingress.validate_h1") action validate_h1(bit<16> value) {
        hdr.h1.setValid();
        hdr.h1.value = value;
    }
    @name("ingress.validate_h2") action validate_h2(bit<16> value) {
        hdr.h2.value = value;
    }
    @name("ingress.validate_h3") action validate_h3(bit<16> value) {
        hdr.h3.setValid();
        hdr.h3.value = value;
    }
    @name("ingress.use_h1_h2_h3") action use_h1_h2_h3() {
        hdr.h4.setValid();
        hdr.h4.value = (hdr.h1.value & (hdr.h2.value | hdr.h3.value)) - (hdr.h1.value | hdr.h2.value & hdr.h3.value);
        meta._ghost_used0 = 1w1;
    }
    @name("ingress.t1") table t1_0 {
        key = {
            hdr.h0.value: exact @name("hdr.h0.value") ;
        }
        actions = {
            validate_h1();
            drop_1();
            @defaultonly NoAction_0();
        }
        default_action = NoAction_0();
    }
    @name("ingress.t2") table t2_0 {
        key = {
            hdr.h0.value: exact @name("hdr.h0.value") ;
        }
        actions = {
            validate_h2();
            drop_5();
            @defaultonly NoAction_5();
        }
        default_action = NoAction_5();
    }
    @name("ingress.t3") table t3_0 {
        key = {
            hdr.h0.value: exact @name("hdr.h0.value") ;
        }
        actions = {
            validate_h3();
            drop_6();
            @defaultonly NoAction_6();
        }
        default_action = NoAction_6();
    }
    @name("ingress.t4") table t4_0 {
        key = {
            hdr.h0.value: exact @name("hdr.h0.value") ;
        }
        actions = {
            use_h1_h2_h3();
            drop_7();
            @defaultonly NoAction_7();
        }
        default_action = NoAction_7();
    }
    apply {
        meta._ghost_used0 = 1w0;
        hdr.h1.setInvalid();
        hdr.h2.setInvalid();
        hdr.h3.setInvalid();
        hdr.h4.setInvalid();
        t1_0.apply();
        t2_0.apply();
        t3_0.apply();
        t4_0.apply();
        if (meta._ghost_used0 == 1w1)  {
            bug();
        } 
        standard_metadata.egress_spec = 9w511;
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
    ;
}
