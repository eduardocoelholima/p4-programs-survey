enum flow_def_schedule_table_0__action_type_t {
    take_video_0,
    _drop_0,
    NoAction_0
}

struct flow_def_schedule_table_0 {
    bool                                     hit;
    bool                                     reach;
    flow_def_schedule_table_0__action_type_t action_run;
    bit<32>                                  take_video_0__dst_ip;
    @matchKind("exact") 
    bit<32>                                  key_schedule_table_0_ipv4_dstAddr;
    @matchKind("range") 
    bit<32>                                  key_schedule_table_0_rtp_timestamp__min;
    @matchKind("range") 
    bit<32>                                  key_schedule_table_0_rtp_timestamp__max;
}

@controlled() extern flow_def_schedule_table_0 query_schedule_table_0(@matchKind("exact") in bit<32> schedule_table_0_ipv4_dstAddr, @matchKind("range") in bit<32> schedule_table_0_rtp_timestamp);
extern void end_schedule_table_0();
extern void key_match(in bool condition);
extern void angelic_assert(in bool condition);
extern void bug();

#include <core.p4>

#include <v1model.p4>

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

header rtp_t {
    bit<2>  version;
    bit<1>  padding;
    bit<1>  extension;
    bit<4>  CSRC_count;
    bit<1>  marker;
    bit<7>  payload_type;
    bit<16> sequence_number;
    bit<32> timestamp;
    bit<32> SSRC;
}

header udp_t {
    bit<16> srcPort;
    bit<16> dstPort;
    bit<16> hdr_length;
    bit<16> checksum;
}

struct metadata {
}

struct headers {
    @name(".ethernet") 
    ethernet_t ethernet;
    @name(".ipv4") 
    ipv4_t     ipv4;
    @name(".rtp") 
    rtp_t      rtp;
    @name(".udp") 
    udp_t      udp;
}

parser ParserImpl(packet_in packet, out headers hdr, inout metadata meta, inout standard_metadata_t standard_metadata) {
    state parse_ipv4 {
        packet.extract<ipv4_t>(hdr.ipv4);
        transition select(hdr.ipv4.protocol) {
            8w0x11: parse_udp;
            default: accept;
        }
    }
    state parse_udp {
        packet.extract<udp_t>(hdr.udp);
        packet.extract<rtp_t>(hdr.rtp);
        transition accept;
    }
    state start {
        packet.extract<ethernet_t>(hdr.ethernet);
        transition select(hdr.ethernet.etherType) {
            16w0x800: parse_ipv4;
            default: accept;
        }
    }
}

control egress(inout headers hdr, inout metadata meta, inout standard_metadata_t standard_metadata) {
    apply {
    }
}

control ingress(inout headers hdr, inout metadata meta, inout standard_metadata_t standard_metadata) {
    bool __track_egress_spec_0;
    @name("ingress.my_direct_counter") direct_counter(CounterType.bytes) my_direct_counter_0;
    apply {
        __track_egress_spec_0 = false;
        {
            flow_def_schedule_table_0 schedule_table;
            schedule_table = query_schedule_table_0(hdr.ipv4.dstAddr, hdr.rtp.timestamp);
            if (schedule_table.hit) {
                key_match(hdr.ipv4.dstAddr == schedule_table.key_schedule_table_0_ipv4_dstAddr && (hdr.rtp.timestamp <= schedule_table.key_schedule_table_0_rtp_timestamp__max && hdr.rtp.timestamp >= schedule_table.key_schedule_table_0_rtp_timestamp__min));
                if (!hdr.ipv4.isValid())  {
                    bug();
                } 
                if (!(hdr.rtp.isValid() && hdr.rtp.isValid() || hdr.rtp.isValid() && !(hdr.rtp.timestamp <= schedule_table.key_schedule_table_0_rtp_timestamp__max) || hdr.rtp.isValid() && !(hdr.rtp.timestamp >= schedule_table.key_schedule_table_0_rtp_timestamp__min)))  {
                    bug();
                } 
            }
            if (schedule_table.action_run == flow_def_schedule_table_0__action_type_t.NoAction_0) {
            }
            else  {
                if (schedule_table.action_run == flow_def_schedule_table_0__action_type_t._drop_0) {
                    angelic_assert(true);
                    {
                        my_direct_counter_0.count();
                        standard_metadata.egress_spec = 9w511;
                        __track_egress_spec_0 = true;
                    }
                }
                else  {
                    if (schedule_table.action_run == flow_def_schedule_table_0__action_type_t.take_video_0) {
                        angelic_assert(true);
                        {
                            my_direct_counter_0.count();
                            standard_metadata.egress_spec = 9w1;
                            __track_egress_spec_0 = true;
                            if (hdr.ipv4.isValid())  {
                                hdr.ipv4.dstAddr = schedule_table.take_video_0__dst_ip;
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
            end_schedule_table_0();
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
        packet.emit<rtp_t>(hdr.rtp);
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
