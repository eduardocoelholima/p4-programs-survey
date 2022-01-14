extern void bug();


// extern bug {
//     bug();
// }

// extern B {
//     B();
//     void bug();
//     void clear();
// }
// @controlled extern clone_session_properties_t qquery_clone_session_properties(in CloneSessionId_t cs);


// extern counter {
//     counter(bit<32> size, CounterType type);
//     void count(in bit<32> index);
// }

// extern bug {
//     bug();
//     void mark_bug();
// }


// extern counter {
//     counter(bit<32> size, CounterType type);
//     void count(in bit<32> index);
// }

// extern void bug();
// extern action_profile {
//     action_profile(bit<32> size);
// }

#include <core.p4>
#define V1MODEL_VERSION 20200408
#include <v1model.p4>

struct ghost_t {
   bit<1> used;
}

header h_t {
   bit<16> value;
}

struct metadata {
    ghost_t ghost;
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
        packet.extract(hdr.h0);
        transition accept;
    }
}

control ingress(inout headers hdr, inout metadata meta, inout standard_metadata_t standard_metadata) {

    action drop_() {
        mark_to_drop(standard_metadata);
    }
    action validate_h1(bit<16> value) {
        hdr.h1.setValid();
        hdr.h1.value = value;
    }
    action validate_h2(bit<16> value) {
        // hdr.h2.setValid();
        hdr.h2.value = value;
    }
    action validate_h3(bit<16> value) {
        hdr.h3.setValid();
        hdr.h3.value = value;
    }
    action use_h1_h2_h3() {
        
        hdr.h4.setValid();
        hdr.h4.value =
           (hdr.h1.value & (hdr.h2.value | hdr.h3.value)) -
           ((hdr.h1.value | (hdr.h2.value & hdr.h3.value)));
        meta.ghost.used = 1w1;
        // assert(hdr.h4.value <= (hdr.h1.value & (hdr.h2.value | hdr.h3.value))); // underflow protection
        // if (!(hdr.h4.value <= (hdr.h1.value & (hdr.h2.value | hdr.h3.value)))) {
        //     bug();
        // }
        

    }
    table t1 {
        key = {
            hdr.h0.value: exact;
        }
        actions = {
           validate_h1;
           drop_;
        }
    }
    table t2 {
        key = {
            hdr.h0.value: exact;
        }
        actions = {
           validate_h2;
           drop_;
        }
    }
    table t3 {
        key = {
            hdr.h0.value: exact;
        }
        actions = {
            validate_h3;
            drop_;
        }
    }
    table t4 {
       key = {
         hdr.h0.value: exact;
       }
       actions = {
         use_h1_h2_h3;
         drop_;
      }
    }
    apply {
      meta.ghost.used = 1w0;
      hdr.h1.setInvalid();
      hdr.h2.setInvalid();
      hdr.h3.setInvalid();
      hdr.h4.setInvalid();
      t1.apply();
      t2.apply();
      t3.apply();
      t4.apply();
    //   if ((meta.ghost.used == 1w1) && (!(hdr.h4.value <= (hdr.h1.value & (hdr.h2.value | hdr.h3.value))))) {
    //         bug();
    //   }  
      if ((meta.ghost.used == 1w1)) {
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
    apply {}
}

control computeChecksum(inout headers hdr, inout metadata meta) {
    apply {}
}

V1Switch(ParserImpl(), verifyChecksum(), ingress(), egress(), computeChecksum(), DeparserImpl()) main;

