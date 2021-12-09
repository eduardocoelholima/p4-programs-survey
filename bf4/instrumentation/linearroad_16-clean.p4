
#include <core.p4>

#include <v1model.p4>

struct egress_metadata_t {
    bit<1> recirculate;
}

struct accident_meta_t {
    bit<8> cur_stp_cnt;
    bit<8> prev_stp_cnt;
    bit<8> accident_seg;
    bit<1> has_accident_ahead;
}

struct seg_metadata_t {
    bit<8>  vol;
    bit<8>  prev_vol;
    bit<16> ewma_spd;
}

struct stopped_metadata_t {
    bit<8> seg0l1;
    bit<8> seg0l2;
    bit<8> seg0l3;
    bit<8> seg1l1;
    bit<8> seg1l2;
    bit<8> seg1l3;
    bit<8> seg2l1;
    bit<8> seg2l2;
    bit<8> seg2l3;
    bit<8> seg3l1;
    bit<8> seg3l2;
    bit<8> seg3l3;
    bit<8> seg4l1;
    bit<8> seg4l2;
    bit<8> seg4l3;
    bit<8> seg0_ord;
    bit<8> seg1_ord;
    bit<8> seg2_ord;
    bit<8> seg3_ord;
    bit<8> seg4_ord;
}

struct travel_estimate_metadata_t {
    bit<1>  recirculated;
    bit<1>  dir;
    bit<8>  seg_cur;
    bit<8>  seg_end;
    bit<16> toll_sum;
    bit<16> time_sum;
}

struct toll_metadata_t {
    bit<16> toll;
    bit<1>  has_toll;
    bit<32> bal;
}

struct v_state_metadata_t {
    bit<1> new;
    bit<1> new_seg;
    bit<8> prev_spd;
    bit<8> prev_xway;
    bit<3> prev_lane;
    bit<8> prev_seg;
    bit<1> prev_dir;
    bit<3> prev_nomove_cnt;
    bit<3> nomove_cnt;
}

header accident_alert_t {
    bit<16> time;
    bit<32> vid;
    bit<16> emit;
    bit<8>  seg;
}

header accnt_bal_t {
    bit<16> time;
    bit<32> vid;
    bit<16> emit;
    bit<32> qid;
    bit<32> bal;
}

header accnt_bal_req_t {
    bit<16> time;
    bit<32> vid;
    bit<32> qid;
}

header ethernet_t {
    bit<48> dstAddr;
    bit<48> srcAddr;
    bit<16> etherType;
}

header expenditure_report_t {
    bit<16> time;
    bit<16> emit;
    bit<32> qid;
    bit<16> bal;
}

header expenditure_req_t {
    bit<16> time;
    bit<32> vid;
    bit<32> qid;
    bit<8>  xway;
    bit<8>  day;
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

header lr_msg_type_t {
    bit<8> msg_type;
}

header pos_report_t {
    bit<16> time;
    bit<32> vid;
    bit<8>  spd;
    bit<8>  xway;
    bit<8>  lane;
    bit<8>  dir;
    bit<8>  seg;
}

header toll_notification_t {
    bit<16> time;
    bit<32> vid;
    bit<16> emit;
    bit<8>  spd;
    bit<16> toll;
}

header travel_estimate_t {
    bit<32> qid;
    bit<16> travel_time;
    bit<16> toll;
}

header travel_estimate_req_t {
    bit<16> time;
    bit<32> qid;
    bit<8>  xway;
    bit<8>  seg_init;
    bit<8>  seg_end;
    bit<8>  dow;
    bit<8>  tod;
}

header udp_t {
    bit<16> srcPort;
    bit<16> dstPort;
    bit<16> length_;
    bit<16> checksum;
}

struct metadata {
    bit<1>  _accident_egress_meta_recirculate0;
    bit<8>  _accident_meta_cur_stp_cnt1;
    bit<8>  _accident_meta_prev_stp_cnt2;
    bit<8>  _accident_meta_accident_seg3;
    bit<1>  _accident_meta_has_accident_ahead4;
    bit<1>  _accnt_bal_egress_meta_recirculate5;
    bit<8>  _seg_meta_vol6;
    bit<8>  _seg_meta_prev_vol7;
    bit<16> _seg_meta_ewma_spd8;
    bit<8>  _stopped_ahead_seg0l19;
    bit<8>  _stopped_ahead_seg0l210;
    bit<8>  _stopped_ahead_seg0l311;
    bit<8>  _stopped_ahead_seg1l112;
    bit<8>  _stopped_ahead_seg1l213;
    bit<8>  _stopped_ahead_seg1l314;
    bit<8>  _stopped_ahead_seg2l115;
    bit<8>  _stopped_ahead_seg2l216;
    bit<8>  _stopped_ahead_seg2l317;
    bit<8>  _stopped_ahead_seg3l118;
    bit<8>  _stopped_ahead_seg3l219;
    bit<8>  _stopped_ahead_seg3l320;
    bit<8>  _stopped_ahead_seg4l121;
    bit<8>  _stopped_ahead_seg4l222;
    bit<8>  _stopped_ahead_seg4l323;
    bit<8>  _stopped_ahead_seg0_ord24;
    bit<8>  _stopped_ahead_seg1_ord25;
    bit<8>  _stopped_ahead_seg2_ord26;
    bit<8>  _stopped_ahead_seg3_ord27;
    bit<8>  _stopped_ahead_seg4_ord28;
    bit<1>  _te_md_recirculated29;
    bit<1>  _te_md_dir30;
    bit<8>  _te_md_seg_cur31;
    bit<8>  _te_md_seg_end32;
    bit<16> _te_md_toll_sum33;
    bit<16> _te_md_time_sum34;
    bit<1>  _toll_egress_meta_recirculate35;
    bit<16> _toll_meta_toll36;
    bit<1>  _toll_meta_has_toll37;
    bit<32> _toll_meta_bal38;
    bit<1>  _v_state_new39;
    bit<1>  _v_state_new_seg40;
    bit<8>  _v_state_prev_spd41;
    bit<8>  _v_state_prev_xway42;
    bit<3>  _v_state_prev_lane43;
    bit<8>  _v_state_prev_seg44;
    bit<1>  _v_state_prev_dir45;
    bit<3>  _v_state_prev_nomove_cnt46;
    bit<3>  _v_state_nomove_cnt47;
}

struct headers {
    @name(".accident_alert") 
    accident_alert_t      accident_alert;
    @name(".accnt_bal") 
    accnt_bal_t           accnt_bal;
    @name(".accnt_bal_req") 
    accnt_bal_req_t       accnt_bal_req;
    @name(".ethernet") 
    ethernet_t            ethernet;
    @name(".expenditure_report") 
    expenditure_report_t  expenditure_report;
    @name(".expenditure_req") 
    expenditure_req_t     expenditure_req;
    @name(".ipv4") 
    ipv4_t                ipv4;
    @name(".lr_msg_type") 
    lr_msg_type_t         lr_msg_type;
    @name(".pos_report") 
    pos_report_t          pos_report;
    @name(".toll_notification") 
    toll_notification_t   toll_notification;
    @name(".travel_estimate") 
    travel_estimate_t     travel_estimate;
    @name(".travel_estimate_req") 
    travel_estimate_req_t travel_estimate_req;
    @name(".udp") 
    udp_t                 udp;
}

parser ParserImpl(packet_in packet, out headers hdr, inout metadata meta, inout standard_metadata_t standard_metadata) {
    @name(".parse_accident_alert") state parse_accident_alert {
        packet.extract<accident_alert_t>(hdr.accident_alert);
        transition accept;
    }
    @name(".parse_accnt_bal") state parse_accnt_bal {
        packet.extract<accnt_bal_t>(hdr.accnt_bal);
        transition accept;
    }
    @name(".parse_accnt_bal_req") state parse_accnt_bal_req {
        packet.extract<accnt_bal_req_t>(hdr.accnt_bal_req);
        transition accept;
    }
    @name(".parse_ethernet") state parse_ethernet {
        packet.extract<ethernet_t>(hdr.ethernet);
        transition select(hdr.ethernet.etherType) {
            16w0x800: parse_ipv4;
            default: accept;
        }
    }
    @name(".parse_expenditure_report") state parse_expenditure_report {
        packet.extract<expenditure_report_t>(hdr.expenditure_report);
        transition accept;
    }
    @name(".parse_expenditure_req") state parse_expenditure_req {
        packet.extract<expenditure_req_t>(hdr.expenditure_req);
        transition accept;
    }
    @name(".parse_ipv4") state parse_ipv4 {
        packet.extract<ipv4_t>(hdr.ipv4);
        transition select(hdr.ipv4.protocol) {
            8w0x11: parse_udp;
            default: accept;
        }
    }
    @name(".parse_lr") state parse_lr {
        packet.extract<lr_msg_type_t>(hdr.lr_msg_type);
        transition select(hdr.lr_msg_type.msg_type) {
            8w0: parse_pos_report;
            8w2: parse_accnt_bal_req;
            8w10: parse_toll_notification;
            8w11: parse_accident_alert;
            8w12: parse_accnt_bal;
            8w3: parse_expenditure_req;
            8w13: parse_expenditure_report;
            8w4: parse_travel_estimate_req;
            8w14: parse_travel_estimate;
            default: accept;
        }
    }
    @name(".parse_pos_report") state parse_pos_report {
        packet.extract<pos_report_t>(hdr.pos_report);
        transition accept;
    }
    @name(".parse_toll_notification") state parse_toll_notification {
        packet.extract<toll_notification_t>(hdr.toll_notification);
        transition accept;
    }
    @name(".parse_travel_estimate") state parse_travel_estimate {
        packet.extract<travel_estimate_t>(hdr.travel_estimate);
        transition accept;
    }
    @name(".parse_travel_estimate_req") state parse_travel_estimate_req {
        packet.extract<travel_estimate_req_t>(hdr.travel_estimate_req);
        transition accept;
    }
    @name(".parse_udp") state parse_udp {
        packet.extract<udp_t>(hdr.udp);
        transition select(hdr.udp.dstPort) {
            16w1234: parse_lr;
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
    @name(".NoAction") action NoAction_1() {
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
    @name(".make_expenditure_report") action make_expenditure_report(bit<16> bal) {
        hdr.lr_msg_type.msg_type = 8w13;
        hdr.expenditure_report.setValid();
        hdr.expenditure_report.time = hdr.expenditure_req.time;
        hdr.expenditure_report.emit = hdr.expenditure_req.time;
        hdr.expenditure_report.qid = hdr.expenditure_req.qid;
        hdr.expenditure_report.bal = bal;
        hdr.expenditure_req.setInvalid();
        hdr.ipv4.totalLen = 16w39;
        hdr.udp.length_ = 16w19;
        hdr.udp.checksum = 16w0;
    }
    @name(".accident_alert_e2e") action accident_alert_e2e(bit<32> mir_ses) {
        meta._accident_egress_meta_recirculate0 = 1w1;
        standard_metadata.clone_spec = 32w1 << 16 | (bit<32>)mir_ses;
    }
    @name(".make_accident_alert") action make_accident_alert() {
        hdr.lr_msg_type.msg_type = 8w11;
        hdr.accident_alert.setValid();
        hdr.accident_alert.time = hdr.pos_report.time;
        hdr.accident_alert.vid = hdr.pos_report.vid;
        hdr.accident_alert.seg = meta._accident_meta_accident_seg3;
        hdr.pos_report.setInvalid();
        hdr.ipv4.totalLen = 16w38;
        hdr.udp.length_ = 16w18;
        hdr.udp.checksum = 16w0;
    }
    @name(".accnt_bal_e2e") action accnt_bal_e2e(bit<32> mir_ses) {
        meta._accnt_bal_egress_meta_recirculate5 = 1w1;
        standard_metadata.clone_spec = 32w2 << 16 | (bit<32>)mir_ses;
    }
    @name(".make_accnt_bal") action make_accnt_bal() {
        hdr.lr_msg_type.msg_type = 8w12;
        hdr.accnt_bal.setValid();
        hdr.accnt_bal.time = hdr.accnt_bal_req.time;
        hdr.accnt_bal.vid = hdr.accnt_bal_req.vid;
        hdr.accnt_bal.qid = hdr.accnt_bal_req.qid;
        hdr.accnt_bal.bal = meta._toll_meta_bal38;
        hdr.accnt_bal_req.setInvalid();
        hdr.ipv4.totalLen = 16w45;
        hdr.udp.length_ = 16w25;
        hdr.udp.checksum = 16w0;
    }
    @name(".rewrite_mac") action rewrite_mac(bit<48> smac) {
        hdr.ethernet.srcAddr = smac;
    }
    @name("._drop") action _drop() {
        standard_metadata.egress_spec = 9w511;
    }
    @name(".toll_notification_e2e") action toll_notification_e2e(bit<32> mir_ses) {
        meta._toll_egress_meta_recirculate35 = 1w1;
        standard_metadata.clone_spec = 32w3 << 16 | (bit<32>)mir_ses;
    }
    @name(".make_toll_notification") action make_toll_notification() {
        hdr.lr_msg_type.msg_type = 8w10;
        hdr.toll_notification.setValid();
        hdr.toll_notification.time = hdr.pos_report.time;
        hdr.toll_notification.vid = hdr.pos_report.vid;
        hdr.toll_notification.spd = (bit<8>)meta._seg_meta_ewma_spd8;
        hdr.toll_notification.toll = meta._toll_meta_toll36;
        hdr.pos_report.setInvalid();
        hdr.ipv4.totalLen = 16w40;
        hdr.udp.length_ = 16w20;
        hdr.udp.checksum = 16w0;
    }
    @name(".update_travel_estimate") action update_travel_estimate(bit<16> time, bit<16> toll) {
        meta._te_md_time_sum34 = meta._te_md_time_sum34 + time;
        meta._te_md_toll_sum33 = meta._te_md_toll_sum33 + toll;
    }
    @name(".do_travel_estimate_init") action do_travel_estimate_init() {
        meta._te_md_dir30 = 1w0;
        meta._te_md_seg_cur31 = hdr.travel_estimate_req.seg_init;
        meta._te_md_seg_end32 = hdr.travel_estimate_req.seg_end;
    }
    @name(".do_travel_estimate_init_rev") action do_travel_estimate_init_rev() {
        meta._te_md_dir30 = 1w1;
        meta._te_md_seg_cur31 = hdr.travel_estimate_req.seg_end;
        meta._te_md_seg_end32 = hdr.travel_estimate_req.seg_init;
    }
    @name(".travel_estimate_e2e") action travel_estimate_e2e(bit<32> mir_ses) {
        meta._te_md_seg_cur31 = meta._te_md_seg_cur31 + 8w1;
        meta._te_md_recirculated29 = 1w1;
        standard_metadata.clone_spec = 32w4 << 16 | (bit<32>)mir_ses;
        standard_metadata.egress_spec = 9w511;
    }
    @name(".do_travel_estimate_send") action do_travel_estimate_send() {
        hdr.lr_msg_type.msg_type = 8w14;
        hdr.travel_estimate.setValid();
        hdr.travel_estimate.qid = hdr.travel_estimate_req.qid;
        hdr.travel_estimate.travel_time = meta._te_md_time_sum34;
        hdr.travel_estimate.toll = meta._te_md_toll_sum33;
        hdr.travel_estimate_req.setInvalid();
        hdr.ipv4.totalLen = 16w37;
        hdr.udp.length_ = 16w17;
        hdr.udp.checksum = 16w0;
    }
    @name(".daily_expenditure") table daily_expenditure_0 {
        actions = {
            make_expenditure_report();
            @defaultonly NoAction_0();
        }
        key = {
            hdr.expenditure_req.vid : exact @name("expenditure_req.vid") ;
            hdr.expenditure_req.day : exact @name("expenditure_req.day") ;
            hdr.expenditure_req.xway: exact @name("expenditure_req.xway") ;
        }
        size = 1024;
        default_action = NoAction_0();
    }
    @name(".send_accident_alert") table send_accident_alert_0 {
        actions = {
            accident_alert_e2e();
            make_accident_alert();
            @defaultonly NoAction_1();
        }
        key = {
            meta._accident_meta_has_accident_ahead4: exact @name("accident_meta.has_accident_ahead") ;
            meta._accident_egress_meta_recirculate0: exact @name("accident_egress_meta.recirculate") ;
        }
        default_action = NoAction_1();
    }
    @name(".send_accnt_bal") table send_accnt_bal_0 {
        actions = {
            accnt_bal_e2e();
            make_accnt_bal();
            @defaultonly NoAction_22();
        }
        key = {
            meta._accnt_bal_egress_meta_recirculate5: exact @name("accnt_bal_egress_meta.recirculate") ;
        }
        default_action = NoAction_22();
    }
    @name(".send_frame") table send_frame_0 {
        actions = {
            rewrite_mac();
            _drop();
            @defaultonly NoAction_23();
        }
        key = {
            standard_metadata.egress_port: exact @name("standard_metadata.egress_port") ;
        }
        size = 256;
        default_action = NoAction_23();
    }
    @name(".send_toll_notification") table send_toll_notification_0 {
        actions = {
            toll_notification_e2e();
            make_toll_notification();
            @defaultonly NoAction_24();
        }
        key = {
            meta._toll_meta_has_toll37          : exact @name("toll_meta.has_toll") ;
            meta._toll_egress_meta_recirculate35: exact @name("toll_egress_meta.recirculate") ;
        }
        default_action = NoAction_24();
    }
    @name(".travel_estimate_history") table travel_estimate_history_0 {
        actions = {
            update_travel_estimate();
            @defaultonly NoAction_25();
        }
        key = {
            hdr.travel_estimate_req.dow : exact @name("travel_estimate_req.dow") ;
            hdr.travel_estimate_req.tod : exact @name("travel_estimate_req.tod") ;
            hdr.travel_estimate_req.xway: exact @name("travel_estimate_req.xway") ;
            meta._te_md_dir30           : exact @name("te_md.dir") ;
            meta._te_md_seg_cur31       : exact @name("te_md.seg_cur") ;
        }
        size = 1024;
        default_action = NoAction_25();
    }
    @name(".travel_estimate_init") table travel_estimate_init_0 {
        actions = {
            do_travel_estimate_init();
        }
        size = 1;
        default_action = do_travel_estimate_init();
    }
    @name(".travel_estimate_init_rev") table travel_estimate_init_rev_0 {
        actions = {
            do_travel_estimate_init_rev();
        }
        size = 1;
        default_action = do_travel_estimate_init_rev();
    }
    @name(".travel_estimate_recirc") table travel_estimate_recirc_0 {
        actions = {
            travel_estimate_e2e();
            @defaultonly NoAction_26();
        }
        size = 1;
        default_action = NoAction_26();
    }
    @name(".travel_estimate_send") table travel_estimate_send_0 {
        actions = {
            do_travel_estimate_send();
        }
        size = 1;
        default_action = do_travel_estimate_send();
    }
    apply {
        if (hdr.ipv4.isValid()) {
            if (hdr.pos_report.isValid()) {
                send_accident_alert_0.apply();
                send_toll_notification_0.apply();
            }
            else  {
                if (hdr.accnt_bal_req.isValid())  {
                    send_accnt_bal_0.apply();
                } 
                else  {
                    if (hdr.expenditure_req.isValid())  {
                        daily_expenditure_0.apply();
                    } 
                    else  {
                        if (hdr.travel_estimate_req.isValid()) {
                            if (meta._te_md_recirculated29 == 1w0)  {
                                if (hdr.travel_estimate_req.seg_init < hdr.travel_estimate_req.seg_end)  {
                                    travel_estimate_init_0.apply();
                                } 
                                else  {
                                    travel_estimate_init_rev_0.apply();
                                }
                            } 
                            travel_estimate_history_0.apply();
                            if (meta._te_md_seg_cur31 == meta._te_md_seg_end32)  {
                                travel_estimate_send_0.apply();
                            } 
                            else  {
                                travel_estimate_recirc_0.apply();
                            }
                        }
                    }
                }
            }
            send_frame_0.apply();
        }
    }
}

control ingress(inout headers hdr, inout metadata meta, inout standard_metadata_t standard_metadata) {
    @name(".NoAction") action NoAction_27() {
    }
    @name(".NoAction") action NoAction_28() {
    }
    @name(".NoAction") action NoAction_29() {
    }
    @name(".NoAction") action NoAction_30() {
    }
    @name(".NoAction") action NoAction_31() {
    }
    @name(".NoAction") action NoAction_32() {
    }
    @name(".NoAction") action NoAction_33() {
    }
    @name(".NoAction") action NoAction_34() {
    }
    @name(".NoAction") action NoAction_35() {
    }
    @name(".NoAction") action NoAction_36() {
    }
    @name(".NoAction") action NoAction_37() {
    }
    @name(".NoAction") action NoAction_38() {
    }
    @name(".NoAction") action NoAction_39() {
    }
    @name(".seg_ewma_spd_reg") register<bit<16>>(32w400) seg_ewma_spd_reg_0;
    @name(".seg_vol_reg") register<bit<8>>(32w400) seg_vol_reg_0;
    @name(".stopped_cnt_reg") register<bit<8>>(32w1200) stopped_cnt_reg_0;
    @name(".v_accnt_bal_reg") register<bit<32>>(32w512) v_accnt_bal_reg_0;
    @name(".v_dir_reg") register<bit<1>>(32w512) v_dir_reg_0;
    @name(".v_lane_reg") register<bit<3>>(32w512) v_lane_reg_0;
    @name(".v_nomove_cnt_reg") register<bit<3>>(32w512) v_nomove_cnt_reg_0;
    @name(".v_seg_reg") register<bit<8>>(32w512) v_seg_reg_0;
    @name(".v_spd_reg") register<bit<8>>(32w512) v_spd_reg_0;
    @name(".v_valid_reg") register<bit<1>>(32w512) v_valid_reg_0;
    @name(".v_xway_reg") register<bit<8>>(32w512) v_xway_reg_0;
    @name(".set_accident_meta") action set_accident_meta(bit<8> ofst) {
        meta._accident_meta_accident_seg3 = hdr.pos_report.seg + ofst;
        meta._accident_meta_has_accident_ahead4 = 1w1;
    }
    @name(".issue_toll") action issue_toll(bit<16> base_toll) {
        meta._toll_meta_has_toll37 = 1w1;
        meta._toll_meta_toll36 = base_toll * ((bit<16>)meta._seg_meta_vol6 + 16w65486) * ((bit<16>)meta._seg_meta_vol6 + 16w65486);
        v_accnt_bal_reg_0.read(meta._toll_meta_bal38, hdr.pos_report.vid);
        meta._toll_meta_bal38 = meta._toll_meta_bal38 + (bit<32>)(base_toll * ((bit<16>)meta._seg_meta_vol6 + 16w65486) * ((bit<16>)meta._seg_meta_vol6 + 16w65486));
        v_accnt_bal_reg_0.write(hdr.pos_report.vid, meta._toll_meta_bal38);
    }
    @name(".do_dec_prev_stopped") action do_dec_prev_stopped() {
        stopped_cnt_reg_0.read(meta._accident_meta_prev_stp_cnt2, (bit<32>)((bit<16>)meta._v_state_prev_xway42 * 16w600 + (bit<16>)(meta._v_state_prev_seg44 << 1) * 16w3 + (bit<16>)meta._v_state_prev_dir45 * 16w3 + (bit<16>)meta._v_state_prev_lane43));
        stopped_cnt_reg_0.write((bit<32>)((bit<16>)meta._v_state_prev_xway42 * 16w600 + (bit<16>)(meta._v_state_prev_seg44 << 1) * 16w3 + (bit<16>)meta._v_state_prev_dir45 * 16w3 + (bit<16>)meta._v_state_prev_lane43), meta._accident_meta_prev_stp_cnt2 + 8w255);
    }
    @name(".set_dmac") action set_dmac(bit<48> dmac) {
        hdr.ethernet.dstAddr = dmac;
    }
    @name("._drop") action _drop_2() {
        standard_metadata.egress_spec = 9w511;
    }
    @name("._drop") action _drop_4() {
        standard_metadata.egress_spec = 9w511;
    }
    @name(".do_inc_stopped") action do_inc_stopped() {
        stopped_cnt_reg_0.read(meta._accident_meta_cur_stp_cnt1, (bit<32>)((bit<16>)hdr.pos_report.xway * 16w600 + (bit<16>)(hdr.pos_report.seg << 1) * 16w3 + (bit<16>)hdr.pos_report.dir * 16w3 + (bit<16>)hdr.pos_report.lane));
        stopped_cnt_reg_0.write((bit<32>)((bit<16>)hdr.pos_report.xway * 16w600 + (bit<16>)(hdr.pos_report.seg << 1) * 16w3 + (bit<16>)hdr.pos_report.dir * 16w3 + (bit<16>)hdr.pos_report.lane), meta._accident_meta_cur_stp_cnt1 + 8w1);
    }
    @name(".set_nhop") action set_nhop(bit<32> nhop_ipv4, bit<9> port) {
        hdr.ipv4.dstAddr = nhop_ipv4;
        standard_metadata.egress_spec = port;
    }
    @name(".do_load_accnt_bal") action do_load_accnt_bal() {
        v_accnt_bal_reg_0.read(meta._toll_meta_bal38, hdr.accnt_bal_req.vid);
    }
    @name(".do_load_stopped_ahead") action do_load_stopped_ahead() {
        stopped_cnt_reg_0.read(meta._stopped_ahead_seg0l19, (bit<32>)((bit<16>)hdr.pos_report.xway * 16w600 + (bit<16>)(hdr.pos_report.seg << 1) * 16w3 + (bit<16>)hdr.pos_report.dir * 16w3 + 16w1));
        stopped_cnt_reg_0.read(meta._stopped_ahead_seg0l210, (bit<32>)((bit<16>)hdr.pos_report.xway * 16w600 + (bit<16>)(hdr.pos_report.seg << 1) * 16w3 + (bit<16>)hdr.pos_report.dir * 16w3 + 16w2));
        stopped_cnt_reg_0.read(meta._stopped_ahead_seg0l311, (bit<32>)((bit<16>)hdr.pos_report.xway * 16w600 + (bit<16>)(hdr.pos_report.seg << 1) * 16w3 + (bit<16>)hdr.pos_report.dir * 16w3 + 16w3));
        stopped_cnt_reg_0.read(meta._stopped_ahead_seg1l112, (bit<32>)((bit<16>)hdr.pos_report.xway * 16w600 + (bit<16>)(hdr.pos_report.seg + 8w1 << 1) * 16w3 + (bit<16>)hdr.pos_report.dir * 16w3 + 16w1));
        stopped_cnt_reg_0.read(meta._stopped_ahead_seg1l213, (bit<32>)((bit<16>)hdr.pos_report.xway * 16w600 + (bit<16>)(hdr.pos_report.seg + 8w1 << 1) * 16w3 + (bit<16>)hdr.pos_report.dir * 16w3 + 16w2));
        stopped_cnt_reg_0.read(meta._stopped_ahead_seg1l314, (bit<32>)((bit<16>)hdr.pos_report.xway * 16w600 + (bit<16>)(hdr.pos_report.seg + 8w1 << 1) * 16w3 + (bit<16>)hdr.pos_report.dir * 16w3 + 16w3));
        stopped_cnt_reg_0.read(meta._stopped_ahead_seg2l115, (bit<32>)((bit<16>)hdr.pos_report.xway * 16w600 + (bit<16>)(hdr.pos_report.seg + 8w2 << 1) * 16w3 + (bit<16>)hdr.pos_report.dir * 16w3 + 16w1));
        stopped_cnt_reg_0.read(meta._stopped_ahead_seg2l216, (bit<32>)((bit<16>)hdr.pos_report.xway * 16w600 + (bit<16>)(hdr.pos_report.seg + 8w2 << 1) * 16w3 + (bit<16>)hdr.pos_report.dir * 16w3 + 16w2));
        stopped_cnt_reg_0.read(meta._stopped_ahead_seg2l317, (bit<32>)((bit<16>)hdr.pos_report.xway * 16w600 + (bit<16>)(hdr.pos_report.seg + 8w2 << 1) * 16w3 + (bit<16>)hdr.pos_report.dir * 16w3 + 16w3));
        stopped_cnt_reg_0.read(meta._stopped_ahead_seg3l118, (bit<32>)((bit<16>)hdr.pos_report.xway * 16w600 + (bit<16>)(hdr.pos_report.seg + 8w3 << 1) * 16w3 + (bit<16>)hdr.pos_report.dir * 16w3 + 16w1));
        stopped_cnt_reg_0.read(meta._stopped_ahead_seg3l219, (bit<32>)((bit<16>)hdr.pos_report.xway * 16w600 + (bit<16>)(hdr.pos_report.seg + 8w3 << 1) * 16w3 + (bit<16>)hdr.pos_report.dir * 16w3 + 16w2));
        stopped_cnt_reg_0.read(meta._stopped_ahead_seg3l320, (bit<32>)((bit<16>)hdr.pos_report.xway * 16w600 + (bit<16>)(hdr.pos_report.seg + 8w3 << 1) * 16w3 + (bit<16>)hdr.pos_report.dir * 16w3 + 16w3));
        stopped_cnt_reg_0.read(meta._stopped_ahead_seg4l121, (bit<32>)((bit<16>)hdr.pos_report.xway * 16w600 + (bit<16>)(hdr.pos_report.seg + 8w4 << 1) * 16w3 + (bit<16>)hdr.pos_report.dir * 16w3 + 16w1));
        stopped_cnt_reg_0.read(meta._stopped_ahead_seg4l222, (bit<32>)((bit<16>)hdr.pos_report.xway * 16w600 + (bit<16>)(hdr.pos_report.seg + 8w4 << 1) * 16w3 + (bit<16>)hdr.pos_report.dir * 16w3 + 16w2));
        stopped_cnt_reg_0.read(meta._stopped_ahead_seg4l323, (bit<32>)((bit<16>)hdr.pos_report.xway * 16w600 + (bit<16>)(hdr.pos_report.seg + 8w4 << 1) * 16w3 + (bit<16>)hdr.pos_report.dir * 16w3 + 16w3));
        meta._stopped_ahead_seg0_ord24 = meta._stopped_ahead_seg0l19 | meta._stopped_ahead_seg0l210 | meta._stopped_ahead_seg0l311;
        meta._stopped_ahead_seg1_ord25 = meta._stopped_ahead_seg1l112 | meta._stopped_ahead_seg1l213 | meta._stopped_ahead_seg1l314;
        meta._stopped_ahead_seg2_ord26 = meta._stopped_ahead_seg2l115 | meta._stopped_ahead_seg2l216 | meta._stopped_ahead_seg2l317;
        meta._stopped_ahead_seg3_ord27 = meta._stopped_ahead_seg3l118 | meta._stopped_ahead_seg3l219 | meta._stopped_ahead_seg3l320;
        meta._stopped_ahead_seg4_ord28 = meta._stopped_ahead_seg4l121 | meta._stopped_ahead_seg4l222 | meta._stopped_ahead_seg4l323;
    }
    @name(".do_loc_changed") action do_loc_changed() {
        v_nomove_cnt_reg_0.read(meta._v_state_prev_nomove_cnt46, hdr.pos_report.vid);
        v_nomove_cnt_reg_0.write(hdr.pos_report.vid, 3w0);
    }
    @name(".do_loc_not_changed") action do_loc_not_changed() {
        v_nomove_cnt_reg_0.read(meta._v_state_prev_nomove_cnt46, hdr.pos_report.vid);
        meta._v_state_nomove_cnt47 = meta._v_state_prev_nomove_cnt46 + 3w1 - ((meta._v_state_prev_nomove_cnt46 + 3w1 & 3w4) >> 2);
        v_nomove_cnt_reg_0.write(hdr.pos_report.vid, meta._v_state_prev_nomove_cnt46 + 3w1 - ((meta._v_state_prev_nomove_cnt46 + 3w1 & 3w4) >> 2));
    }
    @name(".set_spd") action set_spd() {
        meta._seg_meta_ewma_spd8 = (bit<16>)hdr.pos_report.spd;
        seg_ewma_spd_reg_0.write((bit<32>)((bit<16>)hdr.pos_report.xway * 16w200 + (bit<16>)(hdr.pos_report.seg << 1) + (bit<16>)hdr.pos_report.dir), (bit<16>)hdr.pos_report.spd);
    }
    @name(".calc_ewma_spd") action calc_ewma_spd() {
        seg_ewma_spd_reg_0.read(meta._seg_meta_ewma_spd8, (bit<32>)((bit<16>)hdr.pos_report.xway * 16w200 + (bit<16>)(hdr.pos_report.seg << 1) + (bit<16>)hdr.pos_report.dir));
        meta._seg_meta_ewma_spd8 = (bit<16>)((bit<32>)meta._seg_meta_ewma_spd8 * 32w96 + (bit<32>)((bit<16>)hdr.pos_report.spd << 5) >> 7);
        seg_ewma_spd_reg_0.write((bit<32>)((bit<16>)hdr.pos_report.xway * 16w200 + (bit<16>)(hdr.pos_report.seg << 1) + (bit<16>)hdr.pos_report.dir), meta._seg_meta_ewma_spd8);
    }
    @name(".set_new_seg") action set_new_seg() {
        meta._v_state_new_seg40 = 1w1;
    }
    @name(".do_update_pos_state") action do_update_pos_state() {
        v_valid_reg_0.read(meta._v_state_new39, hdr.pos_report.vid);
        meta._v_state_new39 = ~meta._v_state_new39;
        v_spd_reg_0.read(meta._v_state_prev_spd41, hdr.pos_report.vid);
        v_xway_reg_0.read(meta._v_state_prev_xway42, hdr.pos_report.vid);
        v_lane_reg_0.read(meta._v_state_prev_lane43, hdr.pos_report.vid);
        v_seg_reg_0.read(meta._v_state_prev_seg44, hdr.pos_report.vid);
        v_dir_reg_0.read(meta._v_state_prev_dir45, hdr.pos_report.vid);
        v_valid_reg_0.write(hdr.pos_report.vid, 1w1);
        v_spd_reg_0.write(hdr.pos_report.vid, hdr.pos_report.spd);
        v_xway_reg_0.write(hdr.pos_report.vid, hdr.pos_report.xway);
        v_lane_reg_0.write(hdr.pos_report.vid, (bit<3>)hdr.pos_report.lane);
        v_seg_reg_0.write(hdr.pos_report.vid, hdr.pos_report.seg);
        v_dir_reg_0.write(hdr.pos_report.vid, (bit<1>)hdr.pos_report.dir);
    }
    @name(".load_vol") action load_vol() {
        seg_vol_reg_0.read(meta._seg_meta_vol6, (bit<32>)((bit<16>)hdr.pos_report.xway * 16w200 + (bit<16>)(hdr.pos_report.seg << 1) + (bit<16>)hdr.pos_report.dir));
    }
    @name(".load_and_inc_vol") action load_and_inc_vol() {
        seg_vol_reg_0.read(meta._seg_meta_vol6, (bit<32>)((bit<16>)hdr.pos_report.xway * 16w200 + (bit<16>)(hdr.pos_report.seg << 1) + (bit<16>)hdr.pos_report.dir));
        meta._seg_meta_vol6 = meta._seg_meta_vol6 + 8w1;
        seg_vol_reg_0.write((bit<32>)((bit<16>)hdr.pos_report.xway * 16w200 + (bit<16>)(hdr.pos_report.seg << 1) + (bit<16>)hdr.pos_report.dir), meta._seg_meta_vol6);
    }
    @name(".load_and_inc_and_dec_vol") action load_and_inc_and_dec_vol() {
        seg_vol_reg_0.read(meta._seg_meta_vol6, (bit<32>)((bit<16>)hdr.pos_report.xway * 16w200 + (bit<16>)(hdr.pos_report.seg << 1) + (bit<16>)hdr.pos_report.dir));
        meta._seg_meta_vol6 = meta._seg_meta_vol6 + 8w1;
        seg_vol_reg_0.write((bit<32>)((bit<16>)hdr.pos_report.xway * 16w200 + (bit<16>)(hdr.pos_report.seg << 1) + (bit<16>)hdr.pos_report.dir), meta._seg_meta_vol6);
        seg_vol_reg_0.read(meta._seg_meta_prev_vol7, (bit<32>)((bit<16>)meta._v_state_prev_xway42 * 16w200 + (bit<16>)(meta._v_state_prev_seg44 << 1) + (bit<16>)meta._v_state_prev_dir45));
        meta._seg_meta_prev_vol7 = meta._seg_meta_prev_vol7 + 8w255;
        seg_vol_reg_0.write((bit<32>)((bit<16>)meta._v_state_prev_xway42 * 16w200 + (bit<16>)(meta._v_state_prev_seg44 << 1) + (bit<16>)meta._v_state_prev_dir45), meta._seg_meta_prev_vol7);
    }
    @name(".check_accidents") table check_accidents_0 {
        actions = {
            set_accident_meta();
            @defaultonly NoAction_27();
        }
        key = {
            meta._stopped_ahead_seg0_ord24: range @name("stopped_ahead.seg0_ord") ;
            meta._stopped_ahead_seg1_ord25: range @name("stopped_ahead.seg1_ord") ;
            meta._stopped_ahead_seg2_ord26: range @name("stopped_ahead.seg2_ord") ;
            meta._stopped_ahead_seg3_ord27: range @name("stopped_ahead.seg3_ord") ;
            meta._stopped_ahead_seg4_ord28: range @name("stopped_ahead.seg4_ord") ;
        }
        size = 8;
        default_action = NoAction_27();
    }
    @name(".check_toll") table check_toll_0 {
        actions = {
            issue_toll();
            @defaultonly NoAction_28();
        }
        key = {
            meta._v_state_new_seg40                : exact @name("v_state.new_seg") ;
            meta._seg_meta_ewma_spd8               : range @name("seg_meta.ewma_spd") ;
            meta._seg_meta_vol6                    : range @name("seg_meta.vol") ;
            meta._accident_meta_has_accident_ahead4: exact @name("accident_meta.has_accident_ahead") ;
        }
        size = 1;
        default_action = NoAction_28();
    }
    @name(".dec_prev_stopped") table dec_prev_stopped_0 {
        actions = {
            do_dec_prev_stopped();
            @defaultonly NoAction_29();
        }
        default_action = NoAction_29();
    }
    @name(".forward") table forward_0 {
        actions = {
            set_dmac();
            _drop_2();
            @defaultonly NoAction_30();
        }
        key = {
            hdr.ipv4.dstAddr: exact @name("ipv4.dstAddr") ;
        }
        size = 512;
        default_action = NoAction_30();
    }
    @name(".inc_stopped") table inc_stopped_0 {
        actions = {
            do_inc_stopped();
            @defaultonly NoAction_31();
        }
        default_action = NoAction_31();
    }
    @name(".ipv4_lpm") table ipv4_lpm_0 {
        actions = {
            set_nhop();
            _drop_4();
            @defaultonly NoAction_32();
        }
        key = {
            hdr.ipv4.dstAddr: lpm @name("ipv4.dstAddr") ;
        }
        size = 1024;
        default_action = NoAction_32();
    }
    @name(".load_accnt_bal") table load_accnt_bal_0 {
        actions = {
            do_load_accnt_bal();
            @defaultonly NoAction_33();
        }
        default_action = NoAction_33();
    }
    @name(".load_stopped_ahead") table load_stopped_ahead_0 {
        actions = {
            do_load_stopped_ahead();
            @defaultonly NoAction_34();
        }
        default_action = NoAction_34();
    }
    @name(".loc_changed") table loc_changed_0 {
        actions = {
            do_loc_changed();
            @defaultonly NoAction_35();
        }
        default_action = NoAction_35();
    }
    @name(".loc_not_changed") table loc_not_changed_0 {
        actions = {
            do_loc_not_changed();
            @defaultonly NoAction_36();
        }
        default_action = NoAction_36();
    }
    @name(".update_ewma_spd") table update_ewma_spd_0 {
        actions = {
            set_spd();
            calc_ewma_spd();
        }
        key = {
            meta._seg_meta_vol6: exact @name("seg_meta.vol") ;
        }
        size = 2;
        default_action = calc_ewma_spd();
    }
    @name(".update_new_seg") table update_new_seg_0 {
        actions = {
            set_new_seg();
            @defaultonly NoAction_37();
        }
        default_action = NoAction_37();
    }
    @name(".update_pos_state") table update_pos_state_0 {
        actions = {
            do_update_pos_state();
            @defaultonly NoAction_38();
        }
        default_action = NoAction_38();
    }
    @name(".update_vol_state") table update_vol_state_0 {
        actions = {
            load_vol();
            load_and_inc_vol();
            load_and_inc_and_dec_vol();
            @defaultonly NoAction_39();
        }
        key = {
            meta._v_state_new39    : exact @name("v_state.new") ;
            meta._v_state_new_seg40: exact @name("v_state.new_seg") ;
        }
        size = 4;
        default_action = NoAction_39();
    }
    apply {
        if (hdr.ipv4.isValid()) {
            if (hdr.pos_report.isValid()) {
                update_pos_state_0.apply();
                if (meta._v_state_new39 == 1w1 || meta._v_state_prev_seg44 != hdr.pos_report.seg)  {
                    update_new_seg_0.apply();
                } 
                update_vol_state_0.apply();
                update_ewma_spd_0.apply();
                if (hdr.pos_report.xway == meta._v_state_prev_xway42 && hdr.pos_report.seg == meta._v_state_prev_seg44 && hdr.pos_report.dir == (bit<8>)meta._v_state_prev_dir45 && hdr.pos_report.lane == (bit<8>)meta._v_state_prev_lane43)  {
                    loc_not_changed_0.apply();
                } 
                else  {
                    loc_changed_0.apply();
                }
                if (meta._v_state_prev_nomove_cnt46 == 3w3 && meta._v_state_nomove_cnt47 < 3w3)  {
                    dec_prev_stopped_0.apply();
                } 
                if (meta._v_state_prev_nomove_cnt46 < 3w3 && meta._v_state_nomove_cnt47 == 3w3)  {
                    inc_stopped_0.apply();
                } 
                load_stopped_ahead_0.apply();
                check_accidents_0.apply();
                check_toll_0.apply();
            }
            else  {
                if (hdr.accnt_bal_req.isValid())  {
                    load_accnt_bal_0.apply();
                } 
            }
            ipv4_lpm_0.apply();
            forward_0.apply();
        }
    }
}

control DeparserImpl(packet_out packet, in headers hdr) {
    apply {
        packet.emit<ethernet_t>(hdr.ethernet);
        packet.emit<ipv4_t>(hdr.ipv4);
        packet.emit<udp_t>(hdr.udp);
        packet.emit<lr_msg_type_t>(hdr.lr_msg_type);
        packet.emit<travel_estimate_t>(hdr.travel_estimate);
        packet.emit<travel_estimate_req_t>(hdr.travel_estimate_req);
        packet.emit<expenditure_report_t>(hdr.expenditure_report);
        packet.emit<expenditure_req_t>(hdr.expenditure_req);
        packet.emit<accnt_bal_t>(hdr.accnt_bal);
        packet.emit<accident_alert_t>(hdr.accident_alert);
        packet.emit<toll_notification_t>(hdr.toll_notification);
        packet.emit<accnt_bal_req_t>(hdr.accnt_bal_req);
        packet.emit<pos_report_t>(hdr.pos_report);
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
        verify_checksum<tuple_0, bit<16>>(true, { hdr.ipv4.version, hdr.ipv4.ihl, hdr.ipv4.diffserv, hdr.ipv4.totalLen, hdr.ipv4.identification, hdr.ipv4.flags, hdr.ipv4.fragOffset, hdr.ipv4.ttl, hdr.ipv4.protocol, hdr.ipv4.srcAddr, hdr.ipv4.dstAddr }, hdr.ipv4.hdrChecksum, HashAlgorithm.csum16);
    }
}

control computeChecksum(inout headers hdr, inout metadata meta) {
    apply {
        update_checksum<tuple_0, bit<16>>(true, { hdr.ipv4.version, hdr.ipv4.ihl, hdr.ipv4.diffserv, hdr.ipv4.totalLen, hdr.ipv4.identification, hdr.ipv4.flags, hdr.ipv4.fragOffset, hdr.ipv4.ttl, hdr.ipv4.protocol, hdr.ipv4.srcAddr, hdr.ipv4.dstAddr }, hdr.ipv4.hdrChecksum, HashAlgorithm.csum16);
    }
}

V1Switch<headers, metadata>(ParserImpl(), verifyChecksum(), ingress(), egress(), computeChecksum(), DeparserImpl()) main;

void copy_field_list(in metadata from, inout metadata to, in standard_metadata_t smfrom, inout standard_metadata_t smto, in bit<16> discriminator) {
    if (discriminator == 4) {
        to._te_md_dir30 = from._te_md_dir30;
        to._te_md_recirculated29 = from._te_md_recirculated29;
        to._te_md_seg_cur31 = from._te_md_seg_cur31;
        to._te_md_seg_end32 = from._te_md_seg_end32;
        to._te_md_time_sum34 = from._te_md_time_sum34;
        to._te_md_toll_sum33 = from._te_md_toll_sum33;
    }
    else  {
        if (discriminator == 3) {
            to._seg_meta_ewma_spd8 = from._seg_meta_ewma_spd8;
            to._seg_meta_prev_vol7 = from._seg_meta_prev_vol7;
            to._seg_meta_vol6 = from._seg_meta_vol6;
            to._toll_egress_meta_recirculate35 = from._toll_egress_meta_recirculate35;
            to._toll_meta_bal38 = from._toll_meta_bal38;
            to._toll_meta_has_toll37 = from._toll_meta_has_toll37;
            to._toll_meta_toll36 = from._toll_meta_toll36;
        }
        else  {
            if (discriminator == 2) {
                to._accnt_bal_egress_meta_recirculate5 = from._accnt_bal_egress_meta_recirculate5;
                to._toll_meta_bal38 = from._toll_meta_bal38;
                to._toll_meta_has_toll37 = from._toll_meta_has_toll37;
                to._toll_meta_toll36 = from._toll_meta_toll36;
            }
            else  {
                if (discriminator == 1) {
                    to._accident_egress_meta_recirculate0 = from._accident_egress_meta_recirculate0;
                    to._accident_meta_accident_seg3 = from._accident_meta_accident_seg3;
                    to._accident_meta_cur_stp_cnt1 = from._accident_meta_cur_stp_cnt1;
                    to._accident_meta_has_accident_ahead4 = from._accident_meta_has_accident_ahead4;
                    to._accident_meta_prev_stp_cnt2 = from._accident_meta_prev_stp_cnt2;
                }
                else  {
                    ;
                }
            }
        }
    }
}
