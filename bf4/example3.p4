// just a cleaned version of example1.p4

#include <core.p4>
#include <v1model.p4>

struct custom_metadata_t {
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

struct metadata {
    custom_metadata_t custom_metadata;
}

struct headers {
    ethernet_t ethernet;
    ipv4_t     ipv4;
    tcp_t      tcp;
    ipv4_t     ipv4_2;
    ipv4_t     ipv4_3;
}


parser ParserImpl(packet_in packet, out headers hdr, inout metadata meta, inout standard_metadata_t standard_metadata) {
    state parse_ethernet {
        packet.extract(hdr.ethernet);
        transition select(hdr.ethernet.etherType) {
            16w0x800: parse_ipv4;
            default: accept;
        }
    }
    state parse_ipv4 {
        packet.extract(hdr.ipv4);
        transition select(hdr.ipv4.protocol) {
            8w6: parse_tcp;
            default: accept;
        }
    }
    state parse_tcp {
        packet.extract(hdr.tcp);
        transition accept;
    }
    state start {
        transition parse_ethernet;
    }
}

control egress(inout headers hdr, inout metadata meta, inout standard_metadata_t standard_metadata) {
    action _drop() {
        mark_to_drop(standard_metadata);
    }
    // action validate_H1() {
    //   hdr.ipv4.setValid();
    // }
    // action validate_H2() {
    //   // hdr.ethernet.setValid();
    //   hdr.ipv4.setValid();
    // }
    // action use_H12 () {
    //   hdr.ipv4.srcAddr = hdr.ipv4.dstAddr;
    //   // hdr.ethernet.srcAddr = hdr.ethernet.dstAddr;
    // }

    // table t1 {
    //   key = {
    //     hdr.ipv4.srcAddr: exact;
    //   }
    //   actions = {
    //     validate_H1;
    //     _drop;
    //   }      
    // }
    // table t2 {
    //   key = {
    //     hdr.ipv4.dstAddr: exact;
    //   }
    //   actions = {
    //     validate_H2;
    //     _drop;
    //   }
    // }
    // table t3 {
    //   key = {
    //     hdr.ipv4.srcAddr + hdr.ipv4.dstAddr: exact @name ("header1");
    //     hdr.ipv4.ttl: exact;
    //   }
    //   actions = {
    //     use_H12;
    //     // _drop;
    //   }
    // }

    apply {
    //     // hdr.ipv4.setInvalid();
    //     hdr.ethernet.setInvalid();
    //     t1.apply();
    //     t2.apply();
    //     t3.apply();
    }
}

control ingress(inout headers hdr, inout metadata meta, inout standard_metadata_t standard_metadata) {
    action _drop() {
        mark_to_drop(standard_metadata);
    }
    action set_dmac(bit<48> dmac) {
        hdr.ethernet.dstAddr = dmac;
    }
    action set_ttl1(bit<8> newTtl) {
        hdr.ipv4.ttl = newTtl;
    }
    action set_ttl2(bit<8> newTtl) {
        hdr.ipv4_2.ttl = newTtl;
    }
    action set_ttl3(bit<8> newTtl) {
        hdr.ipv4_3.ttl = newTtl;
    }
    action decrement_ttl2() {
        hdr.ipv4_2.ttl = hdr.ipv4_2.ttl - 1;
    }
    action decrement_ttl3() {
        decrement_ttl2();
        hdr.ipv4_3.ttl = hdr.ipv4_3.ttl - 1;
    }
    // action reset_ttl() {
    //     if (hdr.ipv4.srcAddr == 0w32) {
    //         hdr.ipv4.ttl = 8w0xFF;
    //     }
    // }
    action copy_ip_src() {
        hdr.ipv4.srcAddr = hdr.ipv4_2.srcAddr;
    }
    action validate_H1() {
      hdr.ipv4.setValid();
    }
    action validate_H2() {
      hdr.ipv4_2.setValid();
    }
    action validate_H3() {
      hdr.ipv4_3.setValid();
    }
    action validate_E() {
      hdr.ethernet.setValid();
    }
    action use_H12 () {
        // hdr.ipv4_2.srcAddr = hdr.ipv4.srcAddr;
        hdr.ipv4.srcAddr = hdr.ipv4_2.srcAddr;
    }

    table t1 {
      key = {
            hdr.ethernet.etherType: exact;
      }
      actions = {
        validate_H2;
        _drop;
      }      
    }
    table t2 {
        key = {
            hdr.ethernet.etherType: exact;
        }
        actions = {
            validate_H3;
            decrement_ttl2;
            _drop;
        }
    }
    table t3 {
        key = {
            hdr.ethernet.etherType: exact;
        }
        actions = {
            decrement_ttl3;
            _drop;
        }
    }

    apply {
        t1.apply();
        t2.apply();
        t3.apply();
        standard_metadata.egress_spec = 9w5;
    }

    // apply {
    //     ipv4_lpm.apply();
    //     forward.apply();
    // }
}

control DeparserImpl(packet_out packet, in headers hdr) {
    apply {
        packet.emit(hdr.ethernet);
        packet.emit(hdr.ipv4);
        packet.emit(hdr.tcp);
    }
}

control verifyChecksum(inout headers hdr, inout metadata meta) {
    apply {
        verify_checksum(true, 
        { hdr.ipv4.version, 
        hdr.ipv4.ihl, 
        hdr.ipv4.diffserv, 
        hdr.ipv4.totalLen, 
        hdr.ipv4.identification, 
        hdr.ipv4.flags, 
        hdr.ipv4.fragOffset, 
        hdr.ipv4.ttl, 
        hdr.ipv4.protocol, 
        hdr.ipv4.srcAddr, 
        hdr.ipv4.dstAddr }, 
        hdr.ipv4.hdrChecksum, 
        HashAlgorithm.csum16);
    }
}

control computeChecksum(inout headers hdr, inout metadata meta) {
    apply {
        update_checksum(true, 
        { hdr.ipv4.version, 
        hdr.ipv4.ihl, 
        hdr.ipv4.diffserv, 
        hdr.ipv4.totalLen, 
        hdr.ipv4.identification, 
        hdr.ipv4.flags, 
        hdr.ipv4.fragOffset, 
        hdr.ipv4.ttl, 
        hdr.ipv4.protocol, 
        hdr.ipv4.srcAddr, 
        hdr.ipv4.dstAddr }, 
        hdr.ipv4.hdrChecksum, 
        HashAlgorithm.csum16);
    }
}

// control break_bf4(inout headers hdr, inout metadata meta, inout standard_metadata_t standard_metadata) {

// action validate_H1() {
//   hdr.ipv4.setValid();
// }

// action validate_H2() {
//   hdr.ethernet.setValid();
// }

// action use_H12 () {
//   hdr.ipv4.srcAddr = hdr.ipv4.dstAddr;
//   hdr.ethernet.srcAddr = hdr.ethernet.dstAddr;
// }


// table t1 {
//   key = {
//     hdr.ipv4.srcAddr: exact;
//   }
//   actions = {
//     validate_H1;
//     mark_to_drop(standard_metadata);
//   }      
// }

// table t2 {
//   key = {
//     hdr.ipv4.srcAddr: exact;
//     hdr.ipv4.dstAddr: exact;
//   }
//   actions = {
//     validate_H2;
//     mark_to_drop(standard_metadata);
//   }
// }

// table t3 {
//   key = {
//     hdr.ipv4.srcAddr: exact;
//     hdr.ipv4.dstAddr: exact;
//     hdr.ipv4.ttl: exact;
//   }
//   actions = {
//     use_H12;
//   }
// }


// apply{
//     hdr.ipv4.setInvalid();
//     hdr.ethernet.setInvalid();
//     t1.apply();
//     t2.apply();
//     t3.apply();
//   }

// }

V1Switch(ParserImpl(), verifyChecksum(), ingress(), egress(), computeChecksum(), DeparserImpl()) main;

