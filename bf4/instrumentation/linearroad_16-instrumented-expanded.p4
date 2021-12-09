enum flow_def_ipv4_lpm_0__action_type_t {
    set_nhop,
    _drop_4,
    NoAction_32
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
enum flow_def_travel_estimate_send_0__action_type_t {
    do_travel_estimate_send
}

struct flow_def_travel_estimate_send_0 {
    bool                                           hit;
    bool                                           reach;
    flow_def_travel_estimate_send_0__action_type_t action_run;
}

@controlled() extern flow_def_travel_estimate_send_0 query_travel_estimate_send_0();
extern void end_travel_estimate_send_0();
enum flow_def_update_ewma_spd_0__action_type_t {
    set_spd,
    calc_ewma_spd
}

struct flow_def_update_ewma_spd_0 {
    bool                                      hit;
    bool                                      reach;
    flow_def_update_ewma_spd_0__action_type_t action_run;
    @matchKind("exact") 
    bit<8>                                    key_update_ewma_spd_0_seg_meta_vol;
}

@controlled() extern flow_def_update_ewma_spd_0 query_update_ewma_spd_0(@matchKind("exact") in bit<8> update_ewma_spd_0_seg_meta_vol);
extern void end_update_ewma_spd_0();
enum flow_def_inc_stopped_0__action_type_t {
    do_inc_stopped
}

struct flow_def_inc_stopped_0 {
    bool                                  hit;
    bool                                  reach;
    flow_def_inc_stopped_0__action_type_t action_run;
}

@controlled() extern flow_def_inc_stopped_0 query_inc_stopped_0();
extern void end_inc_stopped_0();
enum flow_def_dec_prev_stopped_0__action_type_t {
    do_dec_prev_stopped
}

struct flow_def_dec_prev_stopped_0 {
    bool                                       hit;
    bool                                       reach;
    flow_def_dec_prev_stopped_0__action_type_t action_run;
}

@controlled() extern flow_def_dec_prev_stopped_0 query_dec_prev_stopped_0();
extern void end_dec_prev_stopped_0();
enum flow_def_loc_changed_0__action_type_t {
    do_loc_changed
}

struct flow_def_loc_changed_0 {
    bool                                  hit;
    bool                                  reach;
    flow_def_loc_changed_0__action_type_t action_run;
}

@controlled() extern flow_def_loc_changed_0 query_loc_changed_0();
extern void end_loc_changed_0();
enum flow_def_load_stopped_ahead_0__action_type_t {
    do_load_stopped_ahead
}

struct flow_def_load_stopped_ahead_0 {
    bool                                         hit;
    bool                                         reach;
    flow_def_load_stopped_ahead_0__action_type_t action_run;
}

@controlled() extern flow_def_load_stopped_ahead_0 query_load_stopped_ahead_0();
extern void end_load_stopped_ahead_0();
enum flow_def_load_accnt_bal_0__action_type_t {
    do_load_accnt_bal
}

struct flow_def_load_accnt_bal_0 {
    bool                                     hit;
    bool                                     reach;
    flow_def_load_accnt_bal_0__action_type_t action_run;
}

@controlled() extern flow_def_load_accnt_bal_0 query_load_accnt_bal_0();
extern void end_load_accnt_bal_0();
enum flow_def_update_vol_state_0__action_type_t {
    load_vol,
    load_and_inc_vol,
    load_and_inc_and_dec_vol
}

struct flow_def_update_vol_state_0 {
    bool                                       hit;
    bool                                       reach;
    flow_def_update_vol_state_0__action_type_t action_run;
    @matchKind("exact") 
    bit<1>                                     key_update_vol_state_0_v_state_new;
    @matchKind("exact") 
    bit<1>                                     key_update_vol_state_0_v_state_new_seg;
}

@controlled() extern flow_def_update_vol_state_0 query_update_vol_state_0(@matchKind("exact") in bit<1> update_vol_state_0_v_state_new, @matchKind("exact") in bit<1> update_vol_state_0_v_state_new_seg);
extern void end_update_vol_state_0();
enum flow_def_update_pos_state_0__action_type_t {
    do_update_pos_state
}

struct flow_def_update_pos_state_0 {
    bool                                       hit;
    bool                                       reach;
    flow_def_update_pos_state_0__action_type_t action_run;
}

@controlled() extern flow_def_update_pos_state_0 query_update_pos_state_0();
extern void end_update_pos_state_0();
enum flow_def_update_new_seg_0__action_type_t {
    set_new_seg
}

struct flow_def_update_new_seg_0 {
    bool                                     hit;
    bool                                     reach;
    flow_def_update_new_seg_0__action_type_t action_run;
}

@controlled() extern flow_def_update_new_seg_0 query_update_new_seg_0();
extern void end_update_new_seg_0();
enum flow_def_loc_not_changed_0__action_type_t {
    do_loc_not_changed
}

struct flow_def_loc_not_changed_0 {
    bool                                      hit;
    bool                                      reach;
    flow_def_loc_not_changed_0__action_type_t action_run;
}

@controlled() extern flow_def_loc_not_changed_0 query_loc_not_changed_0();
extern void end_loc_not_changed_0();
enum flow_def_send_accnt_bal_0__action_type_t {
    accnt_bal_e2e,
    make_accnt_bal
}

struct flow_def_send_accnt_bal_0 {
    bool                                     hit;
    bool                                     reach;
    flow_def_send_accnt_bal_0__action_type_t action_run;
    bit<32>                                  accnt_bal_e2e__mir_ses;
    @matchKind("exact") 
    bit<1>                                   key_send_accnt_bal_0_accnt_bal_egress_meta_recirculate;
}

@controlled() extern flow_def_send_accnt_bal_0 query_send_accnt_bal_0(@matchKind("exact") in bit<1> send_accnt_bal_0_accnt_bal_egress_meta_recirculate);
extern void end_send_accnt_bal_0();
enum flow_def_daily_expenditure_0__action_type_t {
    make_expenditure_report,
    NoAction_0
}

struct flow_def_daily_expenditure_0 {
    bool                                        hit;
    bool                                        reach;
    flow_def_daily_expenditure_0__action_type_t action_run;
    bit<16>                                     make_expenditure_report__bal;
    @matchKind("exact") 
    bit<32>                                     key_daily_expenditure_0_expenditure_req_vid;
    @matchKind("exact") 
    bit<8>                                      key_daily_expenditure_0_expenditure_req_day;
    @matchKind("exact") 
    bit<8>                                      key_daily_expenditure_0_expenditure_req_xway;
}

@controlled() extern flow_def_daily_expenditure_0 query_daily_expenditure_0(@matchKind("exact") in bit<32> daily_expenditure_0_expenditure_req_vid, @matchKind("exact") in bit<8> daily_expenditure_0_expenditure_req_day, @matchKind("exact") in bit<8> daily_expenditure_0_expenditure_req_xway);
extern void end_daily_expenditure_0();
enum flow_def_send_accident_alert_0__action_type_t {
    accident_alert_e2e,
    make_accident_alert
}

struct flow_def_send_accident_alert_0 {
    bool                                          hit;
    bool                                          reach;
    flow_def_send_accident_alert_0__action_type_t action_run;
    bit<32>                                       accident_alert_e2e__mir_ses;
    @matchKind("exact") 
    bit<1>                                        key_send_accident_alert_0_accident_meta_has_accident_ahead;
    @matchKind("exact") 
    bit<1>                                        key_send_accident_alert_0_accident_egress_meta_recirculate;
}

@controlled() extern flow_def_send_accident_alert_0 query_send_accident_alert_0(@matchKind("exact") in bit<1> send_accident_alert_0_accident_meta_has_accident_ahead, @matchKind("exact") in bit<1> send_accident_alert_0_accident_egress_meta_recirculate);
extern void end_send_accident_alert_0();
enum flow_def_send_frame_0__action_type_t {
    rewrite_mac,
    _drop,
    NoAction_23
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
enum flow_def_travel_estimate_history_0__action_type_t {
    update_travel_estimate,
    NoAction_25
}

struct flow_def_travel_estimate_history_0 {
    bool                                              hit;
    bool                                              reach;
    flow_def_travel_estimate_history_0__action_type_t action_run;
    bit<16>                                           update_travel_estimate__time;
    bit<16>                                           update_travel_estimate__toll;
    @matchKind("exact") 
    bit<8>                                            key_travel_estimate_history_0_travel_estimate_req_dow;
    @matchKind("exact") 
    bit<8>                                            key_travel_estimate_history_0_travel_estimate_req_tod;
    @matchKind("exact") 
    bit<8>                                            key_travel_estimate_history_0_travel_estimate_req_xway;
    @matchKind("exact") 
    bit<1>                                            key_travel_estimate_history_0_te_md_dir;
    @matchKind("exact") 
    bit<8>                                            key_travel_estimate_history_0_te_md_seg_cur;
}

@controlled() extern flow_def_travel_estimate_history_0 query_travel_estimate_history_0(@matchKind("exact") in bit<8> travel_estimate_history_0_travel_estimate_req_dow, @matchKind("exact") in bit<8> travel_estimate_history_0_travel_estimate_req_tod, @matchKind("exact") in bit<8> travel_estimate_history_0_travel_estimate_req_xway, @matchKind("exact") in bit<1> travel_estimate_history_0_te_md_dir, @matchKind("exact") in bit<8> travel_estimate_history_0_te_md_seg_cur);
extern void end_travel_estimate_history_0();
enum flow_def_send_toll_notification_0__action_type_t {
    toll_notification_e2e,
    make_toll_notification
}

struct flow_def_send_toll_notification_0 {
    bool                                             hit;
    bool                                             reach;
    flow_def_send_toll_notification_0__action_type_t action_run;
    bit<32>                                          toll_notification_e2e__mir_ses;
    @matchKind("exact") 
    bit<1>                                           key_send_toll_notification_0_toll_meta_has_toll;
    @matchKind("exact") 
    bit<1>                                           key_send_toll_notification_0_toll_egress_meta_recirculate;
}

@controlled() extern flow_def_send_toll_notification_0 query_send_toll_notification_0(@matchKind("exact") in bit<1> send_toll_notification_0_toll_meta_has_toll, @matchKind("exact") in bit<1> send_toll_notification_0_toll_egress_meta_recirculate);
extern void end_send_toll_notification_0();
enum flow_def_check_toll_0__action_type_t {
    issue_toll,
    NoAction_28
}

struct flow_def_check_toll_0 {
    bool                                 hit;
    bool                                 reach;
    flow_def_check_toll_0__action_type_t action_run;
    bit<16>                              issue_toll__base_toll;
    @matchKind("exact") 
    bit<1>                               key_check_toll_0_v_state_new_seg;
    @matchKind("range") 
    bit<16>                              key_check_toll_0_seg_meta_ewma_spd__min;
    @matchKind("range") 
    bit<16>                              key_check_toll_0_seg_meta_ewma_spd__max;
    @matchKind("range") 
    bit<8>                               key_check_toll_0_seg_meta_vol__min;
    @matchKind("range") 
    bit<8>                               key_check_toll_0_seg_meta_vol__max;
    @matchKind("exact") 
    bit<1>                               key_check_toll_0_accident_meta_has_accident_ahead;
}

@controlled() extern flow_def_check_toll_0 query_check_toll_0(@matchKind("exact") in bit<1> check_toll_0_v_state_new_seg, @matchKind("range") in bit<16> check_toll_0_seg_meta_ewma_spd, @matchKind("range") in bit<8> check_toll_0_seg_meta_vol, @matchKind("exact") in bit<1> check_toll_0_accident_meta_has_accident_ahead);
extern void end_check_toll_0();
enum flow_def_check_accidents_0__action_type_t {
    set_accident_meta,
    NoAction_27
}

struct flow_def_check_accidents_0 {
    bool                                      hit;
    bool                                      reach;
    flow_def_check_accidents_0__action_type_t action_run;
    bit<8>                                    set_accident_meta__ofst;
    @matchKind("range") 
    bit<8>                                    key_check_accidents_0_stopped_ahead_seg0_ord__min;
    @matchKind("range") 
    bit<8>                                    key_check_accidents_0_stopped_ahead_seg0_ord__max;
    @matchKind("range") 
    bit<8>                                    key_check_accidents_0_stopped_ahead_seg1_ord__min;
    @matchKind("range") 
    bit<8>                                    key_check_accidents_0_stopped_ahead_seg1_ord__max;
    @matchKind("range") 
    bit<8>                                    key_check_accidents_0_stopped_ahead_seg2_ord__min;
    @matchKind("range") 
    bit<8>                                    key_check_accidents_0_stopped_ahead_seg2_ord__max;
    @matchKind("range") 
    bit<8>                                    key_check_accidents_0_stopped_ahead_seg3_ord__min;
    @matchKind("range") 
    bit<8>                                    key_check_accidents_0_stopped_ahead_seg3_ord__max;
    @matchKind("range") 
    bit<8>                                    key_check_accidents_0_stopped_ahead_seg4_ord__min;
    @matchKind("range") 
    bit<8>                                    key_check_accidents_0_stopped_ahead_seg4_ord__max;
}

@controlled() extern flow_def_check_accidents_0 query_check_accidents_0(@matchKind("range") in bit<8> check_accidents_0_stopped_ahead_seg0_ord, @matchKind("range") in bit<8> check_accidents_0_stopped_ahead_seg1_ord, @matchKind("range") in bit<8> check_accidents_0_stopped_ahead_seg2_ord, @matchKind("range") in bit<8> check_accidents_0_stopped_ahead_seg3_ord, @matchKind("range") in bit<8> check_accidents_0_stopped_ahead_seg4_ord);
extern void end_check_accidents_0();
enum flow_def_travel_estimate_init_0__action_type_t {
    do_travel_estimate_init
}

struct flow_def_travel_estimate_init_0 {
    bool                                           hit;
    bool                                           reach;
    flow_def_travel_estimate_init_0__action_type_t action_run;
}

@controlled() extern flow_def_travel_estimate_init_0 query_travel_estimate_init_0();
extern void end_travel_estimate_init_0();
enum flow_def_travel_estimate_recirc_0__action_type_t {
    travel_estimate_e2e
}

struct flow_def_travel_estimate_recirc_0 {
    bool                                             hit;
    bool                                             reach;
    flow_def_travel_estimate_recirc_0__action_type_t action_run;
    bit<32>                                          travel_estimate_e2e__mir_ses;
}

@controlled() extern flow_def_travel_estimate_recirc_0 query_travel_estimate_recirc_0();
extern void end_travel_estimate_recirc_0();
enum flow_def_forward_0__action_type_t {
    set_dmac,
    _drop_2,
    NoAction_30
}

struct flow_def_forward_0 {
    bool                              hit;
    bool                              reach;
    flow_def_forward_0__action_type_t action_run;
    bit<48>                           set_dmac__dmac;
    @matchKind("exact") 
    bit<32>                           key_forward_0_ipv4_dstAddr;
}

@controlled() extern flow_def_forward_0 query_forward_0(@matchKind("exact") in bit<32> forward_0_ipv4_dstAddr);
extern void end_forward_0();
enum flow_def_travel_estimate_init_rev_0__action_type_t {
    do_travel_estimate_init_rev
}

struct flow_def_travel_estimate_init_rev_0 {
    bool                                               hit;
    bool                                               reach;
    flow_def_travel_estimate_init_rev_0__action_type_t action_run;
}

@controlled() extern flow_def_travel_estimate_init_rev_0 query_travel_estimate_init_rev_0();
extern void end_travel_estimate_init_rev_0();
extern void key_match(in bool condition);
extern void angelic_assert(in bool condition);
extern void bug();

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
    apply {
        if (hdr.ipv4.isValid()) {
            if (hdr.pos_report.isValid()) {
                {
                    flow_def_send_accident_alert_0 send_accident_alert;
                    send_accident_alert = query_send_accident_alert_0(meta._accident_meta_has_accident_ahead4, meta._accident_egress_meta_recirculate0);
                    if (send_accident_alert.hit) {
                        key_match(meta._accident_meta_has_accident_ahead4 == send_accident_alert.key_send_accident_alert_0_accident_meta_has_accident_ahead && meta._accident_egress_meta_recirculate0 == send_accident_alert.key_send_accident_alert_0_accident_egress_meta_recirculate);
                    }
                    if (send_accident_alert.action_run == flow_def_send_accident_alert_0__action_type_t.make_accident_alert) {
                        angelic_assert(true);
                        {
                            if (hdr.lr_msg_type.isValid())  {
                                hdr.lr_msg_type.msg_type = 8w11;
                            } 
                            else  {
                                bug();
                            }
                            hdr.accident_alert.setValid();
                            if (hdr.pos_report.isValid() && hdr.accident_alert.isValid())  {
                                hdr.accident_alert.time = hdr.pos_report.time;
                            } 
                            else  {
                                bug();
                            }
                            if (hdr.pos_report.isValid() && hdr.accident_alert.isValid())  {
                                hdr.accident_alert.vid = hdr.pos_report.vid;
                            } 
                            else  {
                                bug();
                            }
                            if (hdr.accident_alert.isValid())  {
                                hdr.accident_alert.seg = meta._accident_meta_accident_seg3;
                            } 
                            else  {
                                bug();
                            }
                            hdr.pos_report.setInvalid();
                            if (hdr.ipv4.isValid())  {
                                hdr.ipv4.totalLen = 16w38;
                            } 
                            else  {
                                bug();
                            }
                            if (hdr.udp.isValid())  {
                                hdr.udp.length_ = 16w18;
                            } 
                            else  {
                                bug();
                            }
                            if (hdr.udp.isValid())  {
                                hdr.udp.checksum = 16w0;
                            } 
                            else  {
                                bug();
                            }
                        }
                    }
                    else  {
                        if (send_accident_alert.action_run == flow_def_send_accident_alert_0__action_type_t.accident_alert_e2e) {
                            angelic_assert(true);
                            {
                                meta._accident_egress_meta_recirculate0 = 1w1;
                                standard_metadata.clone_spec = 32w65536 | send_accident_alert.accident_alert_e2e__mir_ses;
                            }
                        }
                        else  {
                            ;
                        }
                    }
                    end_send_accident_alert_0();
                }
                {
                    flow_def_send_toll_notification_0 send_toll_notification;
                    send_toll_notification = query_send_toll_notification_0(meta._toll_meta_has_toll37, meta._toll_egress_meta_recirculate35);
                    if (send_toll_notification.hit) {
                        key_match(meta._toll_meta_has_toll37 == send_toll_notification.key_send_toll_notification_0_toll_meta_has_toll && meta._toll_egress_meta_recirculate35 == send_toll_notification.key_send_toll_notification_0_toll_egress_meta_recirculate);
                    }
                    if (send_toll_notification.action_run == flow_def_send_toll_notification_0__action_type_t.make_toll_notification) {
                        angelic_assert(true);
                        {
                            if (hdr.lr_msg_type.isValid())  {
                                hdr.lr_msg_type.msg_type = 8w10;
                            } 
                            else  {
                                bug();
                            }
                            hdr.toll_notification.setValid();
                            if (hdr.pos_report.isValid() && hdr.toll_notification.isValid())  {
                                hdr.toll_notification.time = hdr.pos_report.time;
                            } 
                            else  {
                                bug();
                            }
                            if (hdr.pos_report.isValid() && hdr.toll_notification.isValid())  {
                                hdr.toll_notification.vid = hdr.pos_report.vid;
                            } 
                            else  {
                                bug();
                            }
                            if (hdr.toll_notification.isValid())  {
                                hdr.toll_notification.spd = (bit<8>)meta._seg_meta_ewma_spd8;
                            } 
                            else  {
                                bug();
                            }
                            if (hdr.toll_notification.isValid())  {
                                hdr.toll_notification.toll = meta._toll_meta_toll36;
                            } 
                            else  {
                                bug();
                            }
                            hdr.pos_report.setInvalid();
                            if (hdr.ipv4.isValid())  {
                                hdr.ipv4.totalLen = 16w40;
                            } 
                            else  {
                                bug();
                            }
                            if (hdr.udp.isValid())  {
                                hdr.udp.length_ = 16w20;
                            } 
                            else  {
                                bug();
                            }
                            if (hdr.udp.isValid())  {
                                hdr.udp.checksum = 16w0;
                            } 
                            else  {
                                bug();
                            }
                        }
                    }
                    else  {
                        if (send_toll_notification.action_run == flow_def_send_toll_notification_0__action_type_t.toll_notification_e2e) {
                            angelic_assert(true);
                            {
                                meta._toll_egress_meta_recirculate35 = 1w1;
                                standard_metadata.clone_spec = 32w196608 | send_toll_notification.toll_notification_e2e__mir_ses;
                            }
                        }
                        else  {
                            ;
                        }
                    }
                    end_send_toll_notification_0();
                }
            }
            else  {
                if (hdr.accnt_bal_req.isValid()) {
                    flow_def_send_accnt_bal_0 send_accnt_bal;
                    send_accnt_bal = query_send_accnt_bal_0(meta._accnt_bal_egress_meta_recirculate5);
                    if (send_accnt_bal.hit) {
                        key_match(meta._accnt_bal_egress_meta_recirculate5 == send_accnt_bal.key_send_accnt_bal_0_accnt_bal_egress_meta_recirculate);
                    }
                    if (send_accnt_bal.action_run == flow_def_send_accnt_bal_0__action_type_t.make_accnt_bal) {
                        angelic_assert(true);
                        {
                            if (hdr.lr_msg_type.isValid())  {
                                hdr.lr_msg_type.msg_type = 8w12;
                            } 
                            else  {
                                bug();
                            }
                            hdr.accnt_bal.setValid();
                            if (hdr.accnt_bal_req.isValid() && hdr.accnt_bal.isValid())  {
                                hdr.accnt_bal.time = hdr.accnt_bal_req.time;
                            } 
                            else  {
                                bug();
                            }
                            if (hdr.accnt_bal_req.isValid() && hdr.accnt_bal.isValid())  {
                                hdr.accnt_bal.vid = hdr.accnt_bal_req.vid;
                            } 
                            else  {
                                bug();
                            }
                            if (hdr.accnt_bal_req.isValid() && hdr.accnt_bal.isValid())  {
                                hdr.accnt_bal.qid = hdr.accnt_bal_req.qid;
                            } 
                            else  {
                                bug();
                            }
                            if (hdr.accnt_bal.isValid())  {
                                hdr.accnt_bal.bal = meta._toll_meta_bal38;
                            } 
                            else  {
                                bug();
                            }
                            hdr.accnt_bal_req.setInvalid();
                            if (hdr.ipv4.isValid())  {
                                hdr.ipv4.totalLen = 16w45;
                            } 
                            else  {
                                bug();
                            }
                            if (hdr.udp.isValid())  {
                                hdr.udp.length_ = 16w25;
                            } 
                            else  {
                                bug();
                            }
                            if (hdr.udp.isValid())  {
                                hdr.udp.checksum = 16w0;
                            } 
                            else  {
                                bug();
                            }
                        }
                    }
                    else  {
                        if (send_accnt_bal.action_run == flow_def_send_accnt_bal_0__action_type_t.accnt_bal_e2e) {
                            angelic_assert(true);
                            {
                                meta._accnt_bal_egress_meta_recirculate5 = 1w1;
                                standard_metadata.clone_spec = 32w131072 | send_accnt_bal.accnt_bal_e2e__mir_ses;
                            }
                        }
                        else  {
                            ;
                        }
                    }
                    end_send_accnt_bal_0();
                }
                else  {
                    if (hdr.expenditure_req.isValid()) {
                        flow_def_daily_expenditure_0 daily_expenditure;
                        daily_expenditure = query_daily_expenditure_0(hdr.expenditure_req.vid, hdr.expenditure_req.day, hdr.expenditure_req.xway);
                        if (daily_expenditure.hit) {
                            key_match(hdr.expenditure_req.vid == daily_expenditure.key_daily_expenditure_0_expenditure_req_vid && hdr.expenditure_req.day == daily_expenditure.key_daily_expenditure_0_expenditure_req_day && hdr.expenditure_req.xway == daily_expenditure.key_daily_expenditure_0_expenditure_req_xway);
                            if (!hdr.expenditure_req.isValid())  {
                                bug();
                            } 
                            if (!hdr.expenditure_req.isValid())  {
                                bug();
                            } 
                            if (!hdr.expenditure_req.isValid())  {
                                bug();
                            } 
                        }
                        if (daily_expenditure.action_run == flow_def_daily_expenditure_0__action_type_t.NoAction_0) {
                        }
                        else  {
                            if (daily_expenditure.action_run == flow_def_daily_expenditure_0__action_type_t.make_expenditure_report) {
                                angelic_assert(true);
                                {
                                    if (hdr.lr_msg_type.isValid())  {
                                        hdr.lr_msg_type.msg_type = 8w13;
                                    } 
                                    else  {
                                        bug();
                                    }
                                    hdr.expenditure_report.setValid();
                                    if (hdr.expenditure_req.isValid() && hdr.expenditure_report.isValid())  {
                                        hdr.expenditure_report.time = hdr.expenditure_req.time;
                                    } 
                                    else  {
                                        bug();
                                    }
                                    if (hdr.expenditure_req.isValid() && hdr.expenditure_report.isValid())  {
                                        hdr.expenditure_report.emit = hdr.expenditure_req.time;
                                    } 
                                    else  {
                                        bug();
                                    }
                                    if (hdr.expenditure_req.isValid() && hdr.expenditure_report.isValid())  {
                                        hdr.expenditure_report.qid = hdr.expenditure_req.qid;
                                    } 
                                    else  {
                                        bug();
                                    }
                                    if (hdr.expenditure_report.isValid())  {
                                        hdr.expenditure_report.bal = daily_expenditure.make_expenditure_report__bal;
                                    } 
                                    else  {
                                        bug();
                                    }
                                    hdr.expenditure_req.setInvalid();
                                    if (hdr.ipv4.isValid())  {
                                        hdr.ipv4.totalLen = 16w39;
                                    } 
                                    else  {
                                        bug();
                                    }
                                    if (hdr.udp.isValid())  {
                                        hdr.udp.length_ = 16w19;
                                    } 
                                    else  {
                                        bug();
                                    }
                                    if (hdr.udp.isValid())  {
                                        hdr.udp.checksum = 16w0;
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
                        end_daily_expenditure_0();
                    }
                    else  {
                        if (hdr.travel_estimate_req.isValid()) {
                            if (meta._te_md_recirculated29 == 1w0)  {
                                if (hdr.travel_estimate_req.isValid() && hdr.travel_estimate_req.isValid())  {
                                    if (hdr.travel_estimate_req.seg_init < hdr.travel_estimate_req.seg_end) {
                                        flow_def_travel_estimate_init_0 travel_estimate_init;
                                        travel_estimate_init = query_travel_estimate_init_0();
                                        ;
                                        if (travel_estimate_init.action_run == flow_def_travel_estimate_init_0__action_type_t.do_travel_estimate_init) {
                                            angelic_assert(true);
                                            {
                                                meta._te_md_dir30 = 1w0;
                                                if (hdr.travel_estimate_req.isValid())  {
                                                    meta._te_md_seg_cur31 = hdr.travel_estimate_req.seg_init;
                                                } 
                                                else  {
                                                    bug();
                                                }
                                                if (hdr.travel_estimate_req.isValid())  {
                                                    meta._te_md_seg_end32 = hdr.travel_estimate_req.seg_end;
                                                } 
                                                else  {
                                                    bug();
                                                }
                                            }
                                        }
                                        else  {
                                            ;
                                        }
                                        end_travel_estimate_init_0();
                                    }
                                    else {
                                        flow_def_travel_estimate_init_rev_0 travel_estimate_init_rev;
                                        travel_estimate_init_rev = query_travel_estimate_init_rev_0();
                                        ;
                                        if (travel_estimate_init_rev.action_run == flow_def_travel_estimate_init_rev_0__action_type_t.do_travel_estimate_init_rev) {
                                            angelic_assert(true);
                                            {
                                                meta._te_md_dir30 = 1w1;
                                                if (hdr.travel_estimate_req.isValid())  {
                                                    meta._te_md_seg_cur31 = hdr.travel_estimate_req.seg_end;
                                                } 
                                                else  {
                                                    bug();
                                                }
                                                if (hdr.travel_estimate_req.isValid())  {
                                                    meta._te_md_seg_end32 = hdr.travel_estimate_req.seg_init;
                                                } 
                                                else  {
                                                    bug();
                                                }
                                            }
                                        }
                                        else  {
                                            ;
                                        }
                                        end_travel_estimate_init_rev_0();
                                    }
                                } 
                                else  {
                                    bug();
                                }
                            } 
                            {
                                flow_def_travel_estimate_history_0 travel_estimate_history;
                                travel_estimate_history = query_travel_estimate_history_0(hdr.travel_estimate_req.dow, hdr.travel_estimate_req.tod, hdr.travel_estimate_req.xway, meta._te_md_dir30, meta._te_md_seg_cur31);
                                if (travel_estimate_history.hit) {
                                    key_match(hdr.travel_estimate_req.dow == travel_estimate_history.key_travel_estimate_history_0_travel_estimate_req_dow && hdr.travel_estimate_req.tod == travel_estimate_history.key_travel_estimate_history_0_travel_estimate_req_tod && hdr.travel_estimate_req.xway == travel_estimate_history.key_travel_estimate_history_0_travel_estimate_req_xway && meta._te_md_dir30 == travel_estimate_history.key_travel_estimate_history_0_te_md_dir && meta._te_md_seg_cur31 == travel_estimate_history.key_travel_estimate_history_0_te_md_seg_cur);
                                    if (!hdr.travel_estimate_req.isValid())  {
                                        bug();
                                    } 
                                    if (!hdr.travel_estimate_req.isValid())  {
                                        bug();
                                    } 
                                    if (!hdr.travel_estimate_req.isValid())  {
                                        bug();
                                    } 
                                }
                                if (travel_estimate_history.action_run == flow_def_travel_estimate_history_0__action_type_t.NoAction_25) {
                                }
                                else  {
                                    if (travel_estimate_history.action_run == flow_def_travel_estimate_history_0__action_type_t.update_travel_estimate) {
                                        angelic_assert(true);
                                        {
                                            meta._te_md_time_sum34 = meta._te_md_time_sum34 + travel_estimate_history.update_travel_estimate__time;
                                            meta._te_md_toll_sum33 = meta._te_md_toll_sum33 + travel_estimate_history.update_travel_estimate__toll;
                                        }
                                    }
                                    else  {
                                        ;
                                    }
                                }
                                end_travel_estimate_history_0();
                            }
                            if (meta._te_md_seg_cur31 == meta._te_md_seg_end32) {
                                flow_def_travel_estimate_send_0 travel_estimate_send;
                                travel_estimate_send = query_travel_estimate_send_0();
                                ;
                                if (travel_estimate_send.action_run == flow_def_travel_estimate_send_0__action_type_t.do_travel_estimate_send) {
                                    angelic_assert(true);
                                    {
                                        if (hdr.lr_msg_type.isValid())  {
                                            hdr.lr_msg_type.msg_type = 8w14;
                                        } 
                                        else  {
                                            bug();
                                        }
                                        hdr.travel_estimate.setValid();
                                        if (hdr.travel_estimate_req.isValid() && hdr.travel_estimate.isValid())  {
                                            hdr.travel_estimate.qid = hdr.travel_estimate_req.qid;
                                        } 
                                        else  {
                                            bug();
                                        }
                                        if (hdr.travel_estimate.isValid())  {
                                            hdr.travel_estimate.travel_time = meta._te_md_time_sum34;
                                        } 
                                        else  {
                                            bug();
                                        }
                                        if (hdr.travel_estimate.isValid())  {
                                            hdr.travel_estimate.toll = meta._te_md_toll_sum33;
                                        } 
                                        else  {
                                            bug();
                                        }
                                        hdr.travel_estimate_req.setInvalid();
                                        if (hdr.ipv4.isValid())  {
                                            hdr.ipv4.totalLen = 16w37;
                                        } 
                                        else  {
                                            bug();
                                        }
                                        if (hdr.udp.isValid())  {
                                            hdr.udp.length_ = 16w17;
                                        } 
                                        else  {
                                            bug();
                                        }
                                        if (hdr.udp.isValid())  {
                                            hdr.udp.checksum = 16w0;
                                        } 
                                        else  {
                                            bug();
                                        }
                                    }
                                }
                                else  {
                                    ;
                                }
                                end_travel_estimate_send_0();
                            }
                            else {
                                flow_def_travel_estimate_recirc_0 travel_estimate_recirc;
                                travel_estimate_recirc = query_travel_estimate_recirc_0();
                                ;
                                if (travel_estimate_recirc.action_run == flow_def_travel_estimate_recirc_0__action_type_t.travel_estimate_e2e) {
                                    angelic_assert(true);
                                    {
                                        meta._te_md_seg_cur31 = meta._te_md_seg_cur31 + 8w1;
                                        meta._te_md_recirculated29 = 1w1;
                                        standard_metadata.clone_spec = 32w262144 | travel_estimate_recirc.travel_estimate_e2e__mir_ses;
                                        standard_metadata.egress_spec = 9w511;
                                    }
                                }
                                else  {
                                    ;
                                }
                                end_travel_estimate_recirc_0();
                            }
                        }
                    }
                }
            }
            {
                flow_def_send_frame_0 send_frame;
                send_frame = query_send_frame_0(standard_metadata.egress_port);
                if (send_frame.hit) {
                    key_match(standard_metadata.egress_port == send_frame.key_send_frame_0_standard_metadata_egress_port);
                }
                if (send_frame.action_run == flow_def_send_frame_0__action_type_t.NoAction_23) {
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
}

control ingress(inout headers hdr, inout metadata meta, inout standard_metadata_t standard_metadata) {
    bool __track_egress_spec_0;
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
    apply {
        __track_egress_spec_0 = false;
        if (hdr.ipv4.isValid()) {
            if (hdr.pos_report.isValid()) {
                {
                    flow_def_update_pos_state_0 update_pos_state;
                    update_pos_state = query_update_pos_state_0();
                    ;
                    if (update_pos_state.action_run == flow_def_update_pos_state_0__action_type_t.do_update_pos_state) {
                        angelic_assert(true);
                        {
                            if (hdr.pos_report.isValid()) {
                                if (hdr.pos_report.vid >= 32w512)  {
                                    bug();
                                } 
                                v_valid_reg_0.read(meta._v_state_new39, hdr.pos_report.vid);
                            }
                            else  {
                                bug();
                            }
                            meta._v_state_new39 = ~meta._v_state_new39;
                            if (hdr.pos_report.isValid()) {
                                if (hdr.pos_report.vid >= 32w512)  {
                                    bug();
                                } 
                                v_spd_reg_0.read(meta._v_state_prev_spd41, hdr.pos_report.vid);
                            }
                            else  {
                                bug();
                            }
                            if (hdr.pos_report.isValid()) {
                                if (hdr.pos_report.vid >= 32w512)  {
                                    bug();
                                } 
                                v_xway_reg_0.read(meta._v_state_prev_xway42, hdr.pos_report.vid);
                            }
                            else  {
                                bug();
                            }
                            if (hdr.pos_report.isValid()) {
                                if (hdr.pos_report.vid >= 32w512)  {
                                    bug();
                                } 
                                v_lane_reg_0.read(meta._v_state_prev_lane43, hdr.pos_report.vid);
                            }
                            else  {
                                bug();
                            }
                            if (hdr.pos_report.isValid()) {
                                if (hdr.pos_report.vid >= 32w512)  {
                                    bug();
                                } 
                                v_seg_reg_0.read(meta._v_state_prev_seg44, hdr.pos_report.vid);
                            }
                            else  {
                                bug();
                            }
                            if (hdr.pos_report.isValid()) {
                                if (hdr.pos_report.vid >= 32w512)  {
                                    bug();
                                } 
                                v_dir_reg_0.read(meta._v_state_prev_dir45, hdr.pos_report.vid);
                            }
                            else  {
                                bug();
                            }
                            if (hdr.pos_report.isValid()) {
                                if (hdr.pos_report.vid >= 32w512)  {
                                    bug();
                                } 
                                v_valid_reg_0.write(hdr.pos_report.vid, 1w1);
                            }
                            else  {
                                bug();
                            }
                            if (hdr.pos_report.isValid() && hdr.pos_report.isValid()) {
                                if (hdr.pos_report.vid >= 32w512)  {
                                    bug();
                                } 
                                v_spd_reg_0.write(hdr.pos_report.vid, hdr.pos_report.spd);
                            }
                            else  {
                                bug();
                            }
                            if (hdr.pos_report.isValid() && hdr.pos_report.isValid()) {
                                if (hdr.pos_report.vid >= 32w512)  {
                                    bug();
                                } 
                                v_xway_reg_0.write(hdr.pos_report.vid, hdr.pos_report.xway);
                            }
                            else  {
                                bug();
                            }
                            if (hdr.pos_report.isValid() && hdr.pos_report.isValid()) {
                                if (hdr.pos_report.vid >= 32w512)  {
                                    bug();
                                } 
                                v_lane_reg_0.write(hdr.pos_report.vid, (bit<3>)hdr.pos_report.lane);
                            }
                            else  {
                                bug();
                            }
                            if (hdr.pos_report.isValid() && hdr.pos_report.isValid()) {
                                if (hdr.pos_report.vid >= 32w512)  {
                                    bug();
                                } 
                                v_seg_reg_0.write(hdr.pos_report.vid, hdr.pos_report.seg);
                            }
                            else  {
                                bug();
                            }
                            if (hdr.pos_report.isValid() && hdr.pos_report.isValid()) {
                                if (hdr.pos_report.vid >= 32w512)  {
                                    bug();
                                } 
                                v_dir_reg_0.write(hdr.pos_report.vid, (bit<1>)hdr.pos_report.dir);
                            }
                            else  {
                                bug();
                            }
                        }
                    }
                    else  {
                        ;
                    }
                    end_update_pos_state_0();
                }
                if (hdr.pos_report.isValid() || meta._v_state_new39 == 1w1)  {
                    if (meta._v_state_new39 == 1w1 || meta._v_state_prev_seg44 != hdr.pos_report.seg) {
                        flow_def_update_new_seg_0 update_new_seg;
                        update_new_seg = query_update_new_seg_0();
                        ;
                        if (update_new_seg.action_run == flow_def_update_new_seg_0__action_type_t.set_new_seg) {
                            angelic_assert(true);
                            {
                                meta._v_state_new_seg40 = 1w1;
                            }
                        }
                        else  {
                            ;
                        }
                        end_update_new_seg_0();
                    }
                } 
                else  {
                    bug();
                }
                {
                    flow_def_update_vol_state_0 update_vol_state;
                    update_vol_state = query_update_vol_state_0(meta._v_state_new39, meta._v_state_new_seg40);
                    if (update_vol_state.hit) {
                        key_match(meta._v_state_new39 == update_vol_state.key_update_vol_state_0_v_state_new && meta._v_state_new_seg40 == update_vol_state.key_update_vol_state_0_v_state_new_seg);
                    }
                    if (update_vol_state.action_run == flow_def_update_vol_state_0__action_type_t.load_and_inc_and_dec_vol) {
                        angelic_assert(true);
                        {
                            if (hdr.pos_report.isValid() && hdr.pos_report.isValid() && hdr.pos_report.isValid()) {
                                if ((bit<32>)((bit<16>)hdr.pos_report.xway * 16w200 + (bit<16>)(hdr.pos_report.seg << 1) + (bit<16>)hdr.pos_report.dir) >= 32w400)  {
                                    bug();
                                } 
                                seg_vol_reg_0.read(meta._seg_meta_vol6, (bit<32>)((bit<16>)hdr.pos_report.xway * 16w200 + (bit<16>)(hdr.pos_report.seg << 1) + (bit<16>)hdr.pos_report.dir));
                            }
                            else  {
                                bug();
                            }
                            meta._seg_meta_vol6 = meta._seg_meta_vol6 + 8w1;
                            if (hdr.pos_report.isValid() && hdr.pos_report.isValid() && hdr.pos_report.isValid()) {
                                if ((bit<32>)((bit<16>)hdr.pos_report.xway * 16w200 + (bit<16>)(hdr.pos_report.seg << 1) + (bit<16>)hdr.pos_report.dir) >= 32w400)  {
                                    bug();
                                } 
                                seg_vol_reg_0.write((bit<32>)((bit<16>)hdr.pos_report.xway * 16w200 + (bit<16>)(hdr.pos_report.seg << 1) + (bit<16>)hdr.pos_report.dir), meta._seg_meta_vol6);
                            }
                            else  {
                                bug();
                            }
                            if ((bit<32>)((bit<16>)meta._v_state_prev_xway42 * 16w200 + (bit<16>)(meta._v_state_prev_seg44 << 1) + (bit<16>)meta._v_state_prev_dir45) >= 32w400)  {
                                bug();
                            } 
                            seg_vol_reg_0.read(meta._seg_meta_prev_vol7, (bit<32>)((bit<16>)meta._v_state_prev_xway42 * 16w200 + (bit<16>)(meta._v_state_prev_seg44 << 1) + (bit<16>)meta._v_state_prev_dir45));
                            meta._seg_meta_prev_vol7 = meta._seg_meta_prev_vol7 + 8w255;
                            if ((bit<32>)((bit<16>)meta._v_state_prev_xway42 * 16w200 + (bit<16>)(meta._v_state_prev_seg44 << 1) + (bit<16>)meta._v_state_prev_dir45) >= 32w400)  {
                                bug();
                            } 
                            seg_vol_reg_0.write((bit<32>)((bit<16>)meta._v_state_prev_xway42 * 16w200 + (bit<16>)(meta._v_state_prev_seg44 << 1) + (bit<16>)meta._v_state_prev_dir45), meta._seg_meta_prev_vol7);
                        }
                    }
                    else  {
                        if (update_vol_state.action_run == flow_def_update_vol_state_0__action_type_t.load_and_inc_vol) {
                            angelic_assert(true);
                            {
                                if (hdr.pos_report.isValid() && hdr.pos_report.isValid() && hdr.pos_report.isValid()) {
                                    if ((bit<32>)((bit<16>)hdr.pos_report.xway * 16w200 + (bit<16>)(hdr.pos_report.seg << 1) + (bit<16>)hdr.pos_report.dir) >= 32w400)  {
                                        bug();
                                    } 
                                    seg_vol_reg_0.read(meta._seg_meta_vol6, (bit<32>)((bit<16>)hdr.pos_report.xway * 16w200 + (bit<16>)(hdr.pos_report.seg << 1) + (bit<16>)hdr.pos_report.dir));
                                }
                                else  {
                                    bug();
                                }
                                meta._seg_meta_vol6 = meta._seg_meta_vol6 + 8w1;
                                if (hdr.pos_report.isValid() && hdr.pos_report.isValid() && hdr.pos_report.isValid()) {
                                    if ((bit<32>)((bit<16>)hdr.pos_report.xway * 16w200 + (bit<16>)(hdr.pos_report.seg << 1) + (bit<16>)hdr.pos_report.dir) >= 32w400)  {
                                        bug();
                                    } 
                                    seg_vol_reg_0.write((bit<32>)((bit<16>)hdr.pos_report.xway * 16w200 + (bit<16>)(hdr.pos_report.seg << 1) + (bit<16>)hdr.pos_report.dir), meta._seg_meta_vol6);
                                }
                                else  {
                                    bug();
                                }
                            }
                        }
                        else  {
                            if (update_vol_state.action_run == flow_def_update_vol_state_0__action_type_t.load_vol) {
                                angelic_assert(true);
                                {
                                    if (hdr.pos_report.isValid() && hdr.pos_report.isValid() && hdr.pos_report.isValid()) {
                                        if ((bit<32>)((bit<16>)hdr.pos_report.xway * 16w200 + (bit<16>)(hdr.pos_report.seg << 1) + (bit<16>)hdr.pos_report.dir) >= 32w400)  {
                                            bug();
                                        } 
                                        seg_vol_reg_0.read(meta._seg_meta_vol6, (bit<32>)((bit<16>)hdr.pos_report.xway * 16w200 + (bit<16>)(hdr.pos_report.seg << 1) + (bit<16>)hdr.pos_report.dir));
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
                    end_update_vol_state_0();
                }
                {
                    flow_def_update_ewma_spd_0 update_ewma_spd;
                    update_ewma_spd = query_update_ewma_spd_0(meta._seg_meta_vol6);
                    if (update_ewma_spd.hit) {
                        key_match(meta._seg_meta_vol6 == update_ewma_spd.key_update_ewma_spd_0_seg_meta_vol);
                    }
                    if (update_ewma_spd.action_run == flow_def_update_ewma_spd_0__action_type_t.calc_ewma_spd) {
                        angelic_assert(true);
                        {
                            if (hdr.pos_report.isValid() && hdr.pos_report.isValid() && hdr.pos_report.isValid()) {
                                if ((bit<32>)((bit<16>)hdr.pos_report.xway * 16w200 + (bit<16>)(hdr.pos_report.seg << 1) + (bit<16>)hdr.pos_report.dir) >= 32w400)  {
                                    bug();
                                } 
                                seg_ewma_spd_reg_0.read(meta._seg_meta_ewma_spd8, (bit<32>)((bit<16>)hdr.pos_report.xway * 16w200 + (bit<16>)(hdr.pos_report.seg << 1) + (bit<16>)hdr.pos_report.dir));
                            }
                            else  {
                                bug();
                            }
                            meta._seg_meta_ewma_spd8 = (bit<16>)((bit<32>)meta._seg_meta_ewma_spd8 * 32w96 + (bit<32>)((bit<16>)hdr.pos_report.spd << 5) >> 7);
                            if (hdr.pos_report.isValid() && hdr.pos_report.isValid() && hdr.pos_report.isValid()) {
                                if ((bit<32>)((bit<16>)hdr.pos_report.xway * 16w200 + (bit<16>)(hdr.pos_report.seg << 1) + (bit<16>)hdr.pos_report.dir) >= 32w400)  {
                                    bug();
                                } 
                                seg_ewma_spd_reg_0.write((bit<32>)((bit<16>)hdr.pos_report.xway * 16w200 + (bit<16>)(hdr.pos_report.seg << 1) + (bit<16>)hdr.pos_report.dir), meta._seg_meta_ewma_spd8);
                            }
                            else  {
                                bug();
                            }
                        }
                    }
                    else  {
                        if (update_ewma_spd.action_run == flow_def_update_ewma_spd_0__action_type_t.set_spd) {
                            angelic_assert(true);
                            {
                                if (hdr.pos_report.isValid())  {
                                    meta._seg_meta_ewma_spd8 = (bit<16>)hdr.pos_report.spd;
                                } 
                                else  {
                                    bug();
                                }
                                if (hdr.pos_report.isValid() && (hdr.pos_report.isValid() && hdr.pos_report.isValid() && hdr.pos_report.isValid())) {
                                    if ((bit<32>)((bit<16>)hdr.pos_report.xway * 16w200 + (bit<16>)(hdr.pos_report.seg << 1) + (bit<16>)hdr.pos_report.dir) >= 32w400)  {
                                        bug();
                                    } 
                                    seg_ewma_spd_reg_0.write((bit<32>)((bit<16>)hdr.pos_report.xway * 16w200 + (bit<16>)(hdr.pos_report.seg << 1) + (bit<16>)hdr.pos_report.dir), (bit<16>)hdr.pos_report.spd);
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
                    end_update_ewma_spd_0();
                }
                if (((hdr.pos_report.isValid() && hdr.pos_report.isValid() || hdr.pos_report.isValid() && hdr.pos_report.xway != meta._v_state_prev_xway42 || hdr.pos_report.isValid() && hdr.pos_report.seg != meta._v_state_prev_seg44) && hdr.pos_report.isValid() || (hdr.pos_report.isValid() && hdr.pos_report.isValid() || hdr.pos_report.isValid() && hdr.pos_report.xway != meta._v_state_prev_xway42 || hdr.pos_report.isValid() && hdr.pos_report.seg != meta._v_state_prev_seg44) && !(hdr.pos_report.xway == meta._v_state_prev_xway42 && hdr.pos_report.seg == meta._v_state_prev_seg44) || hdr.pos_report.isValid() && hdr.pos_report.dir != (bit<8>)meta._v_state_prev_dir45) && hdr.pos_report.isValid() || ((hdr.pos_report.isValid() && hdr.pos_report.isValid() || hdr.pos_report.isValid() && hdr.pos_report.xway != meta._v_state_prev_xway42 || hdr.pos_report.isValid() && hdr.pos_report.seg != meta._v_state_prev_seg44) && hdr.pos_report.isValid() || (hdr.pos_report.isValid() && hdr.pos_report.isValid() || hdr.pos_report.isValid() && hdr.pos_report.xway != meta._v_state_prev_xway42 || hdr.pos_report.isValid() && hdr.pos_report.seg != meta._v_state_prev_seg44) && !(hdr.pos_report.xway == meta._v_state_prev_xway42 && hdr.pos_report.seg == meta._v_state_prev_seg44) || hdr.pos_report.isValid() && hdr.pos_report.dir != (bit<8>)meta._v_state_prev_dir45) && !(hdr.pos_report.xway == meta._v_state_prev_xway42 && hdr.pos_report.seg == meta._v_state_prev_seg44 && hdr.pos_report.dir == (bit<8>)meta._v_state_prev_dir45) || hdr.pos_report.isValid() && hdr.pos_report.lane != (bit<8>)meta._v_state_prev_lane43)  {
                    if (hdr.pos_report.xway == meta._v_state_prev_xway42 && hdr.pos_report.seg == meta._v_state_prev_seg44 && hdr.pos_report.dir == (bit<8>)meta._v_state_prev_dir45 && hdr.pos_report.lane == (bit<8>)meta._v_state_prev_lane43) {
                        flow_def_loc_not_changed_0 loc_not_changed;
                        loc_not_changed = query_loc_not_changed_0();
                        ;
                        if (loc_not_changed.action_run == flow_def_loc_not_changed_0__action_type_t.do_loc_not_changed) {
                            angelic_assert(true);
                            {
                                if (hdr.pos_report.isValid()) {
                                    if (hdr.pos_report.vid >= 32w512)  {
                                        bug();
                                    } 
                                    v_nomove_cnt_reg_0.read(meta._v_state_prev_nomove_cnt46, hdr.pos_report.vid);
                                }
                                else  {
                                    bug();
                                }
                                meta._v_state_nomove_cnt47 = meta._v_state_prev_nomove_cnt46 + 3w1 - ((meta._v_state_prev_nomove_cnt46 + 3w1 & 3w4) >> 2);
                                if (hdr.pos_report.isValid()) {
                                    if (hdr.pos_report.vid >= 32w512)  {
                                        bug();
                                    } 
                                    v_nomove_cnt_reg_0.write(hdr.pos_report.vid, meta._v_state_prev_nomove_cnt46 + 3w1 - ((meta._v_state_prev_nomove_cnt46 + 3w1 & 3w4) >> 2));
                                }
                                else  {
                                    bug();
                                }
                            }
                        }
                        else  {
                            ;
                        }
                        end_loc_not_changed_0();
                    }
                    else {
                        flow_def_loc_changed_0 loc_changed;
                        loc_changed = query_loc_changed_0();
                        ;
                        if (loc_changed.action_run == flow_def_loc_changed_0__action_type_t.do_loc_changed) {
                            angelic_assert(true);
                            {
                                if (hdr.pos_report.isValid()) {
                                    if (hdr.pos_report.vid >= 32w512)  {
                                        bug();
                                    } 
                                    v_nomove_cnt_reg_0.read(meta._v_state_prev_nomove_cnt46, hdr.pos_report.vid);
                                }
                                else  {
                                    bug();
                                }
                                if (hdr.pos_report.isValid()) {
                                    if (hdr.pos_report.vid >= 32w512)  {
                                        bug();
                                    } 
                                    v_nomove_cnt_reg_0.write(hdr.pos_report.vid, 3w0);
                                }
                                else  {
                                    bug();
                                }
                            }
                        }
                        else  {
                            ;
                        }
                        end_loc_changed_0();
                    }
                } 
                else  {
                    bug();
                }
                if (meta._v_state_prev_nomove_cnt46 == 3w3 && meta._v_state_nomove_cnt47 < 3w3) {
                    flow_def_dec_prev_stopped_0 dec_prev_stopped;
                    dec_prev_stopped = query_dec_prev_stopped_0();
                    ;
                    if (dec_prev_stopped.action_run == flow_def_dec_prev_stopped_0__action_type_t.do_dec_prev_stopped) {
                        angelic_assert(true);
                        {
                            if ((bit<32>)((bit<16>)meta._v_state_prev_xway42 * 16w600 + (bit<16>)(meta._v_state_prev_seg44 << 1) * 16w3 + (bit<16>)meta._v_state_prev_dir45 * 16w3 + (bit<16>)meta._v_state_prev_lane43) >= 32w1200)  {
                                bug();
                            } 
                            stopped_cnt_reg_0.read(meta._accident_meta_prev_stp_cnt2, (bit<32>)((bit<16>)meta._v_state_prev_xway42 * 16w600 + (bit<16>)(meta._v_state_prev_seg44 << 1) * 16w3 + (bit<16>)meta._v_state_prev_dir45 * 16w3 + (bit<16>)meta._v_state_prev_lane43));
                            if ((bit<32>)((bit<16>)meta._v_state_prev_xway42 * 16w600 + (bit<16>)(meta._v_state_prev_seg44 << 1) * 16w3 + (bit<16>)meta._v_state_prev_dir45 * 16w3 + (bit<16>)meta._v_state_prev_lane43) >= 32w1200)  {
                                bug();
                            } 
                            stopped_cnt_reg_0.write((bit<32>)((bit<16>)meta._v_state_prev_xway42 * 16w600 + (bit<16>)(meta._v_state_prev_seg44 << 1) * 16w3 + (bit<16>)meta._v_state_prev_dir45 * 16w3 + (bit<16>)meta._v_state_prev_lane43), meta._accident_meta_prev_stp_cnt2 + 8w255);
                        }
                    }
                    else  {
                        ;
                    }
                    end_dec_prev_stopped_0();
                }
                if (meta._v_state_prev_nomove_cnt46 < 3w3 && meta._v_state_nomove_cnt47 == 3w3) {
                    flow_def_inc_stopped_0 inc_stopped;
                    inc_stopped = query_inc_stopped_0();
                    ;
                    if (inc_stopped.action_run == flow_def_inc_stopped_0__action_type_t.do_inc_stopped) {
                        angelic_assert(true);
                        {
                            if (hdr.pos_report.isValid() && hdr.pos_report.isValid() && hdr.pos_report.isValid() && hdr.pos_report.isValid()) {
                                if ((bit<32>)((bit<16>)hdr.pos_report.xway * 16w600 + (bit<16>)(hdr.pos_report.seg << 1) * 16w3 + (bit<16>)hdr.pos_report.dir * 16w3 + (bit<16>)hdr.pos_report.lane) >= 32w1200)  {
                                    bug();
                                } 
                                stopped_cnt_reg_0.read(meta._accident_meta_cur_stp_cnt1, (bit<32>)((bit<16>)hdr.pos_report.xway * 16w600 + (bit<16>)(hdr.pos_report.seg << 1) * 16w3 + (bit<16>)hdr.pos_report.dir * 16w3 + (bit<16>)hdr.pos_report.lane));
                            }
                            else  {
                                bug();
                            }
                            if (hdr.pos_report.isValid() && hdr.pos_report.isValid() && hdr.pos_report.isValid() && hdr.pos_report.isValid()) {
                                if ((bit<32>)((bit<16>)hdr.pos_report.xway * 16w600 + (bit<16>)(hdr.pos_report.seg << 1) * 16w3 + (bit<16>)hdr.pos_report.dir * 16w3 + (bit<16>)hdr.pos_report.lane) >= 32w1200)  {
                                    bug();
                                } 
                                stopped_cnt_reg_0.write((bit<32>)((bit<16>)hdr.pos_report.xway * 16w600 + (bit<16>)(hdr.pos_report.seg << 1) * 16w3 + (bit<16>)hdr.pos_report.dir * 16w3 + (bit<16>)hdr.pos_report.lane), meta._accident_meta_cur_stp_cnt1 + 8w1);
                            }
                            else  {
                                bug();
                            }
                        }
                    }
                    else  {
                        ;
                    }
                    end_inc_stopped_0();
                }
                {
                    flow_def_load_stopped_ahead_0 load_stopped_ahead;
                    load_stopped_ahead = query_load_stopped_ahead_0();
                    ;
                    if (load_stopped_ahead.action_run == flow_def_load_stopped_ahead_0__action_type_t.do_load_stopped_ahead) {
                        angelic_assert(true);
                        {
                            if (hdr.pos_report.isValid() && hdr.pos_report.isValid() && hdr.pos_report.isValid()) {
                                if ((bit<32>)((bit<16>)hdr.pos_report.xway * 16w600 + (bit<16>)(hdr.pos_report.seg << 1) * 16w3 + (bit<16>)hdr.pos_report.dir * 16w3 + 16w1) >= 32w1200)  {
                                    bug();
                                } 
                                stopped_cnt_reg_0.read(meta._stopped_ahead_seg0l19, (bit<32>)((bit<16>)hdr.pos_report.xway * 16w600 + (bit<16>)(hdr.pos_report.seg << 1) * 16w3 + (bit<16>)hdr.pos_report.dir * 16w3 + 16w1));
                            }
                            else  {
                                bug();
                            }
                            if (hdr.pos_report.isValid() && hdr.pos_report.isValid() && hdr.pos_report.isValid()) {
                                if ((bit<32>)((bit<16>)hdr.pos_report.xway * 16w600 + (bit<16>)(hdr.pos_report.seg << 1) * 16w3 + (bit<16>)hdr.pos_report.dir * 16w3 + 16w2) >= 32w1200)  {
                                    bug();
                                } 
                                stopped_cnt_reg_0.read(meta._stopped_ahead_seg0l210, (bit<32>)((bit<16>)hdr.pos_report.xway * 16w600 + (bit<16>)(hdr.pos_report.seg << 1) * 16w3 + (bit<16>)hdr.pos_report.dir * 16w3 + 16w2));
                            }
                            else  {
                                bug();
                            }
                            if (hdr.pos_report.isValid() && hdr.pos_report.isValid() && hdr.pos_report.isValid()) {
                                if ((bit<32>)((bit<16>)hdr.pos_report.xway * 16w600 + (bit<16>)(hdr.pos_report.seg << 1) * 16w3 + (bit<16>)hdr.pos_report.dir * 16w3 + 16w3) >= 32w1200)  {
                                    bug();
                                } 
                                stopped_cnt_reg_0.read(meta._stopped_ahead_seg0l311, (bit<32>)((bit<16>)hdr.pos_report.xway * 16w600 + (bit<16>)(hdr.pos_report.seg << 1) * 16w3 + (bit<16>)hdr.pos_report.dir * 16w3 + 16w3));
                            }
                            else  {
                                bug();
                            }
                            if (hdr.pos_report.isValid() && hdr.pos_report.isValid() && hdr.pos_report.isValid()) {
                                if ((bit<32>)((bit<16>)hdr.pos_report.xway * 16w600 + (bit<16>)(hdr.pos_report.seg + 8w1 << 1) * 16w3 + (bit<16>)hdr.pos_report.dir * 16w3 + 16w1) >= 32w1200)  {
                                    bug();
                                } 
                                stopped_cnt_reg_0.read(meta._stopped_ahead_seg1l112, (bit<32>)((bit<16>)hdr.pos_report.xway * 16w600 + (bit<16>)(hdr.pos_report.seg + 8w1 << 1) * 16w3 + (bit<16>)hdr.pos_report.dir * 16w3 + 16w1));
                            }
                            else  {
                                bug();
                            }
                            if (hdr.pos_report.isValid() && hdr.pos_report.isValid() && hdr.pos_report.isValid()) {
                                if ((bit<32>)((bit<16>)hdr.pos_report.xway * 16w600 + (bit<16>)(hdr.pos_report.seg + 8w1 << 1) * 16w3 + (bit<16>)hdr.pos_report.dir * 16w3 + 16w2) >= 32w1200)  {
                                    bug();
                                } 
                                stopped_cnt_reg_0.read(meta._stopped_ahead_seg1l213, (bit<32>)((bit<16>)hdr.pos_report.xway * 16w600 + (bit<16>)(hdr.pos_report.seg + 8w1 << 1) * 16w3 + (bit<16>)hdr.pos_report.dir * 16w3 + 16w2));
                            }
                            else  {
                                bug();
                            }
                            if (hdr.pos_report.isValid() && hdr.pos_report.isValid() && hdr.pos_report.isValid()) {
                                if ((bit<32>)((bit<16>)hdr.pos_report.xway * 16w600 + (bit<16>)(hdr.pos_report.seg + 8w1 << 1) * 16w3 + (bit<16>)hdr.pos_report.dir * 16w3 + 16w3) >= 32w1200)  {
                                    bug();
                                } 
                                stopped_cnt_reg_0.read(meta._stopped_ahead_seg1l314, (bit<32>)((bit<16>)hdr.pos_report.xway * 16w600 + (bit<16>)(hdr.pos_report.seg + 8w1 << 1) * 16w3 + (bit<16>)hdr.pos_report.dir * 16w3 + 16w3));
                            }
                            else  {
                                bug();
                            }
                            if (hdr.pos_report.isValid() && hdr.pos_report.isValid() && hdr.pos_report.isValid()) {
                                if ((bit<32>)((bit<16>)hdr.pos_report.xway * 16w600 + (bit<16>)(hdr.pos_report.seg + 8w2 << 1) * 16w3 + (bit<16>)hdr.pos_report.dir * 16w3 + 16w1) >= 32w1200)  {
                                    bug();
                                } 
                                stopped_cnt_reg_0.read(meta._stopped_ahead_seg2l115, (bit<32>)((bit<16>)hdr.pos_report.xway * 16w600 + (bit<16>)(hdr.pos_report.seg + 8w2 << 1) * 16w3 + (bit<16>)hdr.pos_report.dir * 16w3 + 16w1));
                            }
                            else  {
                                bug();
                            }
                            if (hdr.pos_report.isValid() && hdr.pos_report.isValid() && hdr.pos_report.isValid()) {
                                if ((bit<32>)((bit<16>)hdr.pos_report.xway * 16w600 + (bit<16>)(hdr.pos_report.seg + 8w2 << 1) * 16w3 + (bit<16>)hdr.pos_report.dir * 16w3 + 16w2) >= 32w1200)  {
                                    bug();
                                } 
                                stopped_cnt_reg_0.read(meta._stopped_ahead_seg2l216, (bit<32>)((bit<16>)hdr.pos_report.xway * 16w600 + (bit<16>)(hdr.pos_report.seg + 8w2 << 1) * 16w3 + (bit<16>)hdr.pos_report.dir * 16w3 + 16w2));
                            }
                            else  {
                                bug();
                            }
                            if (hdr.pos_report.isValid() && hdr.pos_report.isValid() && hdr.pos_report.isValid()) {
                                if ((bit<32>)((bit<16>)hdr.pos_report.xway * 16w600 + (bit<16>)(hdr.pos_report.seg + 8w2 << 1) * 16w3 + (bit<16>)hdr.pos_report.dir * 16w3 + 16w3) >= 32w1200)  {
                                    bug();
                                } 
                                stopped_cnt_reg_0.read(meta._stopped_ahead_seg2l317, (bit<32>)((bit<16>)hdr.pos_report.xway * 16w600 + (bit<16>)(hdr.pos_report.seg + 8w2 << 1) * 16w3 + (bit<16>)hdr.pos_report.dir * 16w3 + 16w3));
                            }
                            else  {
                                bug();
                            }
                            if (hdr.pos_report.isValid() && hdr.pos_report.isValid() && hdr.pos_report.isValid()) {
                                if ((bit<32>)((bit<16>)hdr.pos_report.xway * 16w600 + (bit<16>)(hdr.pos_report.seg + 8w3 << 1) * 16w3 + (bit<16>)hdr.pos_report.dir * 16w3 + 16w1) >= 32w1200)  {
                                    bug();
                                } 
                                stopped_cnt_reg_0.read(meta._stopped_ahead_seg3l118, (bit<32>)((bit<16>)hdr.pos_report.xway * 16w600 + (bit<16>)(hdr.pos_report.seg + 8w3 << 1) * 16w3 + (bit<16>)hdr.pos_report.dir * 16w3 + 16w1));
                            }
                            else  {
                                bug();
                            }
                            if (hdr.pos_report.isValid() && hdr.pos_report.isValid() && hdr.pos_report.isValid()) {
                                if ((bit<32>)((bit<16>)hdr.pos_report.xway * 16w600 + (bit<16>)(hdr.pos_report.seg + 8w3 << 1) * 16w3 + (bit<16>)hdr.pos_report.dir * 16w3 + 16w2) >= 32w1200)  {
                                    bug();
                                } 
                                stopped_cnt_reg_0.read(meta._stopped_ahead_seg3l219, (bit<32>)((bit<16>)hdr.pos_report.xway * 16w600 + (bit<16>)(hdr.pos_report.seg + 8w3 << 1) * 16w3 + (bit<16>)hdr.pos_report.dir * 16w3 + 16w2));
                            }
                            else  {
                                bug();
                            }
                            if (hdr.pos_report.isValid() && hdr.pos_report.isValid() && hdr.pos_report.isValid()) {
                                if ((bit<32>)((bit<16>)hdr.pos_report.xway * 16w600 + (bit<16>)(hdr.pos_report.seg + 8w3 << 1) * 16w3 + (bit<16>)hdr.pos_report.dir * 16w3 + 16w3) >= 32w1200)  {
                                    bug();
                                } 
                                stopped_cnt_reg_0.read(meta._stopped_ahead_seg3l320, (bit<32>)((bit<16>)hdr.pos_report.xway * 16w600 + (bit<16>)(hdr.pos_report.seg + 8w3 << 1) * 16w3 + (bit<16>)hdr.pos_report.dir * 16w3 + 16w3));
                            }
                            else  {
                                bug();
                            }
                            if (hdr.pos_report.isValid() && hdr.pos_report.isValid() && hdr.pos_report.isValid()) {
                                if ((bit<32>)((bit<16>)hdr.pos_report.xway * 16w600 + (bit<16>)(hdr.pos_report.seg + 8w4 << 1) * 16w3 + (bit<16>)hdr.pos_report.dir * 16w3 + 16w1) >= 32w1200)  {
                                    bug();
                                } 
                                stopped_cnt_reg_0.read(meta._stopped_ahead_seg4l121, (bit<32>)((bit<16>)hdr.pos_report.xway * 16w600 + (bit<16>)(hdr.pos_report.seg + 8w4 << 1) * 16w3 + (bit<16>)hdr.pos_report.dir * 16w3 + 16w1));
                            }
                            else  {
                                bug();
                            }
                            if (hdr.pos_report.isValid() && hdr.pos_report.isValid() && hdr.pos_report.isValid()) {
                                if ((bit<32>)((bit<16>)hdr.pos_report.xway * 16w600 + (bit<16>)(hdr.pos_report.seg + 8w4 << 1) * 16w3 + (bit<16>)hdr.pos_report.dir * 16w3 + 16w2) >= 32w1200)  {
                                    bug();
                                } 
                                stopped_cnt_reg_0.read(meta._stopped_ahead_seg4l222, (bit<32>)((bit<16>)hdr.pos_report.xway * 16w600 + (bit<16>)(hdr.pos_report.seg + 8w4 << 1) * 16w3 + (bit<16>)hdr.pos_report.dir * 16w3 + 16w2));
                            }
                            else  {
                                bug();
                            }
                            if (hdr.pos_report.isValid() && hdr.pos_report.isValid() && hdr.pos_report.isValid()) {
                                if ((bit<32>)((bit<16>)hdr.pos_report.xway * 16w600 + (bit<16>)(hdr.pos_report.seg + 8w4 << 1) * 16w3 + (bit<16>)hdr.pos_report.dir * 16w3 + 16w3) >= 32w1200)  {
                                    bug();
                                } 
                                stopped_cnt_reg_0.read(meta._stopped_ahead_seg4l323, (bit<32>)((bit<16>)hdr.pos_report.xway * 16w600 + (bit<16>)(hdr.pos_report.seg + 8w4 << 1) * 16w3 + (bit<16>)hdr.pos_report.dir * 16w3 + 16w3));
                            }
                            else  {
                                bug();
                            }
                            meta._stopped_ahead_seg0_ord24 = meta._stopped_ahead_seg0l19 | meta._stopped_ahead_seg0l210 | meta._stopped_ahead_seg0l311;
                            meta._stopped_ahead_seg1_ord25 = meta._stopped_ahead_seg1l112 | meta._stopped_ahead_seg1l213 | meta._stopped_ahead_seg1l314;
                            meta._stopped_ahead_seg2_ord26 = meta._stopped_ahead_seg2l115 | meta._stopped_ahead_seg2l216 | meta._stopped_ahead_seg2l317;
                            meta._stopped_ahead_seg3_ord27 = meta._stopped_ahead_seg3l118 | meta._stopped_ahead_seg3l219 | meta._stopped_ahead_seg3l320;
                            meta._stopped_ahead_seg4_ord28 = meta._stopped_ahead_seg4l121 | meta._stopped_ahead_seg4l222 | meta._stopped_ahead_seg4l323;
                        }
                    }
                    else  {
                        ;
                    }
                    end_load_stopped_ahead_0();
                }
                {
                    flow_def_check_accidents_0 check_accidents;
                    check_accidents = query_check_accidents_0(meta._stopped_ahead_seg0_ord24, meta._stopped_ahead_seg1_ord25, meta._stopped_ahead_seg2_ord26, meta._stopped_ahead_seg3_ord27, meta._stopped_ahead_seg4_ord28);
                    if (check_accidents.hit) {
                        key_match(meta._stopped_ahead_seg0_ord24 <= check_accidents.key_check_accidents_0_stopped_ahead_seg0_ord__max && meta._stopped_ahead_seg0_ord24 >= check_accidents.key_check_accidents_0_stopped_ahead_seg0_ord__min && (meta._stopped_ahead_seg1_ord25 <= check_accidents.key_check_accidents_0_stopped_ahead_seg1_ord__max && meta._stopped_ahead_seg1_ord25 >= check_accidents.key_check_accidents_0_stopped_ahead_seg1_ord__min) && (meta._stopped_ahead_seg2_ord26 <= check_accidents.key_check_accidents_0_stopped_ahead_seg2_ord__max && meta._stopped_ahead_seg2_ord26 >= check_accidents.key_check_accidents_0_stopped_ahead_seg2_ord__min) && (meta._stopped_ahead_seg3_ord27 <= check_accidents.key_check_accidents_0_stopped_ahead_seg3_ord__max && meta._stopped_ahead_seg3_ord27 >= check_accidents.key_check_accidents_0_stopped_ahead_seg3_ord__min) && (meta._stopped_ahead_seg4_ord28 <= check_accidents.key_check_accidents_0_stopped_ahead_seg4_ord__max && meta._stopped_ahead_seg4_ord28 >= check_accidents.key_check_accidents_0_stopped_ahead_seg4_ord__min));
                    }
                    if (check_accidents.action_run == flow_def_check_accidents_0__action_type_t.NoAction_27) {
                    }
                    else  {
                        if (check_accidents.action_run == flow_def_check_accidents_0__action_type_t.set_accident_meta) {
                            angelic_assert(true);
                            {
                                if (hdr.pos_report.isValid())  {
                                    meta._accident_meta_accident_seg3 = hdr.pos_report.seg + check_accidents.set_accident_meta__ofst;
                                } 
                                else  {
                                    bug();
                                }
                                meta._accident_meta_has_accident_ahead4 = 1w1;
                            }
                        }
                        else  {
                            ;
                        }
                    }
                    end_check_accidents_0();
                }
                {
                    flow_def_check_toll_0 check_toll;
                    check_toll = query_check_toll_0(meta._v_state_new_seg40, meta._seg_meta_ewma_spd8, meta._seg_meta_vol6, meta._accident_meta_has_accident_ahead4);
                    if (check_toll.hit) {
                        key_match(meta._v_state_new_seg40 == check_toll.key_check_toll_0_v_state_new_seg && (meta._seg_meta_ewma_spd8 <= check_toll.key_check_toll_0_seg_meta_ewma_spd__max && meta._seg_meta_ewma_spd8 >= check_toll.key_check_toll_0_seg_meta_ewma_spd__min) && (meta._seg_meta_vol6 <= check_toll.key_check_toll_0_seg_meta_vol__max && meta._seg_meta_vol6 >= check_toll.key_check_toll_0_seg_meta_vol__min) && meta._accident_meta_has_accident_ahead4 == check_toll.key_check_toll_0_accident_meta_has_accident_ahead);
                    }
                    if (check_toll.action_run == flow_def_check_toll_0__action_type_t.NoAction_28) {
                    }
                    else  {
                        if (check_toll.action_run == flow_def_check_toll_0__action_type_t.issue_toll) {
                            angelic_assert(true);
                            {
                                meta._toll_meta_has_toll37 = 1w1;
                                meta._toll_meta_toll36 = check_toll.issue_toll__base_toll * ((bit<16>)meta._seg_meta_vol6 + 16w65486) * ((bit<16>)meta._seg_meta_vol6 + 16w65486);
                                if (hdr.pos_report.isValid()) {
                                    if (hdr.pos_report.vid >= 32w512)  {
                                        bug();
                                    } 
                                    v_accnt_bal_reg_0.read(meta._toll_meta_bal38, hdr.pos_report.vid);
                                }
                                else  {
                                    bug();
                                }
                                meta._toll_meta_bal38 = meta._toll_meta_bal38 + (bit<32>)(check_toll.issue_toll__base_toll * ((bit<16>)meta._seg_meta_vol6 + 16w65486) * ((bit<16>)meta._seg_meta_vol6 + 16w65486));
                                if (hdr.pos_report.isValid()) {
                                    if (hdr.pos_report.vid >= 32w512)  {
                                        bug();
                                    } 
                                    v_accnt_bal_reg_0.write(hdr.pos_report.vid, meta._toll_meta_bal38);
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
                    end_check_toll_0();
                }
            }
            else  {
                if (hdr.accnt_bal_req.isValid()) {
                    flow_def_load_accnt_bal_0 load_accnt_bal;
                    load_accnt_bal = query_load_accnt_bal_0();
                    ;
                    if (load_accnt_bal.action_run == flow_def_load_accnt_bal_0__action_type_t.do_load_accnt_bal) {
                        angelic_assert(true);
                        {
                            if (hdr.accnt_bal_req.isValid()) {
                                if (hdr.accnt_bal_req.vid >= 32w512)  {
                                    bug();
                                } 
                                v_accnt_bal_reg_0.read(meta._toll_meta_bal38, hdr.accnt_bal_req.vid);
                            }
                            else  {
                                bug();
                            }
                        }
                    }
                    else  {
                        ;
                    }
                    end_load_accnt_bal_0();
                }
            }
            {
                flow_def_ipv4_lpm_0 ipv4_lpm;
                ipv4_lpm = query_ipv4_lpm_0(hdr.ipv4.dstAddr);
                if (ipv4_lpm.hit) {
                    key_match(hdr.ipv4.dstAddr & (32w1 << ipv4_lpm.key_ipv4_lpm_0_ipv4_dstAddr__prefix) - 32w1 == ipv4_lpm.key_ipv4_lpm_0_ipv4_dstAddr__val & (32w1 << ipv4_lpm.key_ipv4_lpm_0_ipv4_dstAddr__prefix) - 32w1);
                    if (!(hdr.ipv4.isValid() || (32w1 << ipv4_lpm.key_ipv4_lpm_0_ipv4_dstAddr__prefix) - 32w1 == 32w0))  {
                        bug();
                    } 
                }
                if (ipv4_lpm.action_run == flow_def_ipv4_lpm_0__action_type_t.NoAction_32) {
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
                                if (hdr.ipv4.isValid())  {
                                    hdr.ipv4.dstAddr = ipv4_lpm.set_nhop__nhop_ipv4;
                                } 
                                else  {
                                    bug();
                                }
                                standard_metadata.egress_spec = ipv4_lpm.set_nhop__port;
                                __track_egress_spec_0 = true;
                            }
                        }
                        else  {
                            ;
                        }
                    }
                }
                end_ipv4_lpm_0();
            }
            {
                flow_def_forward_0 forward;
                forward = query_forward_0(hdr.ipv4.dstAddr);
                if (forward.hit) {
                    key_match(hdr.ipv4.dstAddr == forward.key_forward_0_ipv4_dstAddr);
                    if (!hdr.ipv4.isValid())  {
                        bug();
                    } 
                }
                if (forward.action_run == flow_def_forward_0__action_type_t.NoAction_30) {
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
    }
}

control computeChecksum(inout headers hdr, inout metadata meta) {
    apply {
    }
}

V1Switch<headers, metadata>(ParserImpl(), verifyChecksum(), ingress(), egress(), computeChecksum(), DeparserImpl()) main;

void copy_field_list(in metadata from, inout metadata to, in standard_metadata_t smfrom, inout standard_metadata_t smto, in bit<16> discriminator) {
    if (discriminator == 16w4) {
        to._te_md_dir30 = from._te_md_dir30;
        to._te_md_recirculated29 = from._te_md_recirculated29;
        to._te_md_seg_cur31 = from._te_md_seg_cur31;
        to._te_md_seg_end32 = from._te_md_seg_end32;
        to._te_md_time_sum34 = from._te_md_time_sum34;
        to._te_md_toll_sum33 = from._te_md_toll_sum33;
    }
    else  {
        if (discriminator == 16w3) {
            to._seg_meta_ewma_spd8 = from._seg_meta_ewma_spd8;
            to._seg_meta_prev_vol7 = from._seg_meta_prev_vol7;
            to._seg_meta_vol6 = from._seg_meta_vol6;
            to._toll_egress_meta_recirculate35 = from._toll_egress_meta_recirculate35;
            to._toll_meta_bal38 = from._toll_meta_bal38;
            to._toll_meta_has_toll37 = from._toll_meta_has_toll37;
            to._toll_meta_toll36 = from._toll_meta_toll36;
        }
        else  {
            if (discriminator == 16w2) {
                to._accnt_bal_egress_meta_recirculate5 = from._accnt_bal_egress_meta_recirculate5;
                to._toll_meta_bal38 = from._toll_meta_bal38;
                to._toll_meta_has_toll37 = from._toll_meta_has_toll37;
                to._toll_meta_toll36 = from._toll_meta_toll36;
            }
            else  {
                if (discriminator == 16w1) {
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
