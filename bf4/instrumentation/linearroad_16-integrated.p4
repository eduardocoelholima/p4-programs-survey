extern H havoc<H>();
extern void assert(in bool condition);
extern void assume(in bool condition);
extern void oob();
extern void dontCare();
extern void do_drop();
extern mutable_packet {
    mutable_packet(int size);
    void extract<T>(out T hdr);
    void extract<T>(out T variableSizeHeader, in bit<32> variableFieldSizeInBits);
    T lookahead<T>();
    void advance(in bit<32> sizeInBits);
    bit<32> length();
    void emit<T>(in T hdr);
}

extern void copyPacket(mutable_packet self, @readonly mutable_packet other);
extern void prependPacket(mutable_packet self, @readonly mutable_packet other);
extern void readPacket(mutable_packet self);
extern void emptyPacket(mutable_packet self);
extern void do_send<H>(in H port, mutable_packet pin);
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

@controlled extern flow_def_ipv4_lpm_0 query_ipv4_lpm_0(@matchKind("lpm") in bit<32> ipv4_lpm_0_ipv4_dstAddr);
extern void end_ipv4_lpm_0();
enum flow_def_travel_estimate_send_0__action_type_t {
    do_travel_estimate_send
}

struct flow_def_travel_estimate_send_0 {
    bool                                           hit;
    bool                                           reach;
    flow_def_travel_estimate_send_0__action_type_t action_run;
}

@controlled extern flow_def_travel_estimate_send_0 query_travel_estimate_send_0();
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

@controlled extern flow_def_update_ewma_spd_0 query_update_ewma_spd_0(@matchKind("exact") in bit<8> update_ewma_spd_0_seg_meta_vol);
extern void end_update_ewma_spd_0();
enum flow_def_inc_stopped_0__action_type_t {
    do_inc_stopped
}

struct flow_def_inc_stopped_0 {
    bool                                  hit;
    bool                                  reach;
    flow_def_inc_stopped_0__action_type_t action_run;
}

@controlled extern flow_def_inc_stopped_0 query_inc_stopped_0();
extern void end_inc_stopped_0();
enum flow_def_dec_prev_stopped_0__action_type_t {
    do_dec_prev_stopped
}

struct flow_def_dec_prev_stopped_0 {
    bool                                       hit;
    bool                                       reach;
    flow_def_dec_prev_stopped_0__action_type_t action_run;
}

@controlled extern flow_def_dec_prev_stopped_0 query_dec_prev_stopped_0();
extern void end_dec_prev_stopped_0();
enum flow_def_loc_changed_0__action_type_t {
    do_loc_changed
}

struct flow_def_loc_changed_0 {
    bool                                  hit;
    bool                                  reach;
    flow_def_loc_changed_0__action_type_t action_run;
}

@controlled extern flow_def_loc_changed_0 query_loc_changed_0();
extern void end_loc_changed_0();
enum flow_def_load_stopped_ahead_0__action_type_t {
    do_load_stopped_ahead
}

struct flow_def_load_stopped_ahead_0 {
    bool                                         hit;
    bool                                         reach;
    flow_def_load_stopped_ahead_0__action_type_t action_run;
}

@controlled extern flow_def_load_stopped_ahead_0 query_load_stopped_ahead_0();
extern void end_load_stopped_ahead_0();
enum flow_def_load_accnt_bal_0__action_type_t {
    do_load_accnt_bal
}

struct flow_def_load_accnt_bal_0 {
    bool                                     hit;
    bool                                     reach;
    flow_def_load_accnt_bal_0__action_type_t action_run;
}

@controlled extern flow_def_load_accnt_bal_0 query_load_accnt_bal_0();
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

@controlled extern flow_def_update_vol_state_0 query_update_vol_state_0(@matchKind("exact") in bit<1> update_vol_state_0_v_state_new, @matchKind("exact") in bit<1> update_vol_state_0_v_state_new_seg);
extern void end_update_vol_state_0();
enum flow_def_update_pos_state_0__action_type_t {
    do_update_pos_state
}

struct flow_def_update_pos_state_0 {
    bool                                       hit;
    bool                                       reach;
    flow_def_update_pos_state_0__action_type_t action_run;
}

@controlled extern flow_def_update_pos_state_0 query_update_pos_state_0();
extern void end_update_pos_state_0();
enum flow_def_update_new_seg_0__action_type_t {
    set_new_seg
}

struct flow_def_update_new_seg_0 {
    bool                                     hit;
    bool                                     reach;
    flow_def_update_new_seg_0__action_type_t action_run;
}

@controlled extern flow_def_update_new_seg_0 query_update_new_seg_0();
extern void end_update_new_seg_0();
enum flow_def_loc_not_changed_0__action_type_t {
    do_loc_not_changed
}

struct flow_def_loc_not_changed_0 {
    bool                                      hit;
    bool                                      reach;
    flow_def_loc_not_changed_0__action_type_t action_run;
}

@controlled extern flow_def_loc_not_changed_0 query_loc_not_changed_0();
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

@controlled extern flow_def_send_accnt_bal_0 query_send_accnt_bal_0(@matchKind("exact") in bit<1> send_accnt_bal_0_accnt_bal_egress_meta_recirculate);
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

@controlled extern flow_def_daily_expenditure_0 query_daily_expenditure_0(@matchKind("exact") in bit<32> daily_expenditure_0_expenditure_req_vid, @matchKind("exact") in bit<8> daily_expenditure_0_expenditure_req_day, @matchKind("exact") in bit<8> daily_expenditure_0_expenditure_req_xway);
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

@controlled extern flow_def_send_accident_alert_0 query_send_accident_alert_0(@matchKind("exact") in bit<1> send_accident_alert_0_accident_meta_has_accident_ahead, @matchKind("exact") in bit<1> send_accident_alert_0_accident_egress_meta_recirculate);
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

@controlled extern flow_def_send_frame_0 query_send_frame_0(@matchKind("exact") in bit<9> send_frame_0_standard_metadata_egress_port);
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

@controlled extern flow_def_travel_estimate_history_0 query_travel_estimate_history_0(@matchKind("exact") in bit<8> travel_estimate_history_0_travel_estimate_req_dow, @matchKind("exact") in bit<8> travel_estimate_history_0_travel_estimate_req_tod, @matchKind("exact") in bit<8> travel_estimate_history_0_travel_estimate_req_xway, @matchKind("exact") in bit<1> travel_estimate_history_0_te_md_dir, @matchKind("exact") in bit<8> travel_estimate_history_0_te_md_seg_cur);
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

@controlled extern flow_def_send_toll_notification_0 query_send_toll_notification_0(@matchKind("exact") in bit<1> send_toll_notification_0_toll_meta_has_toll, @matchKind("exact") in bit<1> send_toll_notification_0_toll_egress_meta_recirculate);
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

@controlled extern flow_def_check_toll_0 query_check_toll_0(@matchKind("exact") in bit<1> check_toll_0_v_state_new_seg, @matchKind("range") in bit<16> check_toll_0_seg_meta_ewma_spd, @matchKind("range") in bit<8> check_toll_0_seg_meta_vol, @matchKind("exact") in bit<1> check_toll_0_accident_meta_has_accident_ahead);
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

@controlled extern flow_def_check_accidents_0 query_check_accidents_0(@matchKind("range") in bit<8> check_accidents_0_stopped_ahead_seg0_ord, @matchKind("range") in bit<8> check_accidents_0_stopped_ahead_seg1_ord, @matchKind("range") in bit<8> check_accidents_0_stopped_ahead_seg2_ord, @matchKind("range") in bit<8> check_accidents_0_stopped_ahead_seg3_ord, @matchKind("range") in bit<8> check_accidents_0_stopped_ahead_seg4_ord);
extern void end_check_accidents_0();
enum flow_def_travel_estimate_init_0__action_type_t {
    do_travel_estimate_init
}

struct flow_def_travel_estimate_init_0 {
    bool                                           hit;
    bool                                           reach;
    flow_def_travel_estimate_init_0__action_type_t action_run;
}

@controlled extern flow_def_travel_estimate_init_0 query_travel_estimate_init_0();
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

@controlled extern flow_def_travel_estimate_recirc_0 query_travel_estimate_recirc_0();
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

@controlled extern flow_def_forward_0 query_forward_0(@matchKind("exact") in bit<32> forward_0_ipv4_dstAddr);
extern void end_forward_0();
enum flow_def_travel_estimate_init_rev_0__action_type_t {
    do_travel_estimate_init_rev
}

struct flow_def_travel_estimate_init_rev_0 {
    bool                                               hit;
    bool                                               reach;
    flow_def_travel_estimate_init_rev_0__action_type_t action_run;
}

@controlled extern flow_def_travel_estimate_init_rev_0 query_travel_estimate_init_rev_0();
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

parser ParserImpl(mutable_packet packet, out headers hdr, inout metadata meta, inout standard_metadata_t standard_metadata, inout error err) {
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
    flow_def_send_accident_alert_0 send_accident_alert;
    flow_def_send_toll_notification_0 send_toll_notification;
    flow_def_send_accnt_bal_0 send_accnt_bal;
    flow_def_daily_expenditure_0 daily_expenditure;
    flow_def_travel_estimate_init_0 travel_estimate_init;
    flow_def_travel_estimate_init_rev_0 travel_estimate_init_rev;
    flow_def_travel_estimate_history_0 travel_estimate_history;
    flow_def_travel_estimate_send_0 travel_estimate_send;
    flow_def_travel_estimate_recirc_0 travel_estimate_recirc;
    flow_def_send_frame_0 send_frame;
    flow_def_send_accident_alert_0 tmp_23;
    flow_def_send_toll_notification_0 tmp_24;
    flow_def_send_accnt_bal_0 tmp_25;
    flow_def_daily_expenditure_0 tmp_26;
    flow_def_travel_estimate_init_0 tmp_27;
    flow_def_travel_estimate_init_rev_0 tmp_28;
    flow_def_travel_estimate_history_0 tmp_29;
    flow_def_travel_estimate_send_0 tmp_30;
    flow_def_travel_estimate_recirc_0 tmp_31;
    flow_def_send_frame_0 tmp_32;
    apply {
        if (hdr.ipv4.isValid()) {
            if (hdr.pos_report.isValid()) {
                tmp_23 = query_send_accident_alert_0(meta._accident_meta_has_accident_ahead4, meta._accident_egress_meta_recirculate0);
                send_accident_alert = tmp_23;
                if (send_accident_alert.hit) {
                    key_match(meta._accident_meta_has_accident_ahead4 == send_accident_alert.key_send_accident_alert_0_accident_meta_has_accident_ahead && meta._accident_egress_meta_recirculate0 == send_accident_alert.key_send_accident_alert_0_accident_egress_meta_recirculate);
                }
                if (send_accident_alert.action_run == flow_def_send_accident_alert_0__action_type_t.make_accident_alert) {
                    angelic_assert(true);
                    if (hdr.lr_msg_type.isValid()) {
                        hdr.lr_msg_type.msg_type = 8w11;
                    }
                    else {
                        bug();
                    }
                    hdr.accident_alert.setValid();
                    if (hdr.pos_report.isValid() && hdr.accident_alert.isValid()) {
                        hdr.accident_alert.time = hdr.pos_report.time;
                    }
                    else {
                        bug();
                    }
                    if (hdr.pos_report.isValid() && hdr.accident_alert.isValid()) {
                        hdr.accident_alert.vid = hdr.pos_report.vid;
                    }
                    else {
                        bug();
                    }
                    if (hdr.accident_alert.isValid()) {
                        hdr.accident_alert.seg = meta._accident_meta_accident_seg3;
                    }
                    else {
                        bug();
                    }
                    hdr.pos_report.setInvalid();
                    if (hdr.ipv4.isValid()) {
                        hdr.ipv4.totalLen = 16w38;
                    }
                    else {
                        bug();
                    }
                    if (hdr.udp.isValid()) {
                        hdr.udp.length_ = 16w18;
                    }
                    else {
                        bug();
                    }
                    if (hdr.udp.isValid()) {
                        hdr.udp.checksum = 16w0;
                    }
                    else {
                        bug();
                    }
                }
                else {
                    if (send_accident_alert.action_run == flow_def_send_accident_alert_0__action_type_t.accident_alert_e2e) {
                        angelic_assert(true);
                        meta._accident_egress_meta_recirculate0 = 1w1;
                        standard_metadata.clone_spec = 32w65536 | send_accident_alert.accident_alert_e2e__mir_ses;
                    }
                    else {
                        ;
                    }
                }
                end_send_accident_alert_0();
                tmp_24 = query_send_toll_notification_0(meta._toll_meta_has_toll37, meta._toll_egress_meta_recirculate35);
                send_toll_notification = tmp_24;
                if (send_toll_notification.hit) {
                    key_match(meta._toll_meta_has_toll37 == send_toll_notification.key_send_toll_notification_0_toll_meta_has_toll && meta._toll_egress_meta_recirculate35 == send_toll_notification.key_send_toll_notification_0_toll_egress_meta_recirculate);
                }
                if (send_toll_notification.action_run == flow_def_send_toll_notification_0__action_type_t.make_toll_notification) {
                    angelic_assert(true);
                    if (hdr.lr_msg_type.isValid()) {
                        hdr.lr_msg_type.msg_type = 8w10;
                    }
                    else {
                        bug();
                    }
                    hdr.toll_notification.setValid();
                    if (hdr.pos_report.isValid() && hdr.toll_notification.isValid()) {
                        hdr.toll_notification.time = hdr.pos_report.time;
                    }
                    else {
                        bug();
                    }
                    if (hdr.pos_report.isValid() && hdr.toll_notification.isValid()) {
                        hdr.toll_notification.vid = hdr.pos_report.vid;
                    }
                    else {
                        bug();
                    }
                    if (hdr.toll_notification.isValid()) {
                        hdr.toll_notification.spd = (bit<8>)meta._seg_meta_ewma_spd8;
                    }
                    else {
                        bug();
                    }
                    if (hdr.toll_notification.isValid()) {
                        hdr.toll_notification.toll = meta._toll_meta_toll36;
                    }
                    else {
                        bug();
                    }
                    hdr.pos_report.setInvalid();
                    if (hdr.ipv4.isValid()) {
                        hdr.ipv4.totalLen = 16w40;
                    }
                    else {
                        bug();
                    }
                    if (hdr.udp.isValid()) {
                        hdr.udp.length_ = 16w20;
                    }
                    else {
                        bug();
                    }
                    if (hdr.udp.isValid()) {
                        hdr.udp.checksum = 16w0;
                    }
                    else {
                        bug();
                    }
                }
                else {
                    if (send_toll_notification.action_run == flow_def_send_toll_notification_0__action_type_t.toll_notification_e2e) {
                        angelic_assert(true);
                        meta._toll_egress_meta_recirculate35 = 1w1;
                        standard_metadata.clone_spec = 32w196608 | send_toll_notification.toll_notification_e2e__mir_ses;
                    }
                    else {
                        ;
                    }
                }
                end_send_toll_notification_0();
            }
            else {
                if (hdr.accnt_bal_req.isValid()) {
                    tmp_25 = query_send_accnt_bal_0(meta._accnt_bal_egress_meta_recirculate5);
                    send_accnt_bal = tmp_25;
                    if (send_accnt_bal.hit) {
                        key_match(meta._accnt_bal_egress_meta_recirculate5 == send_accnt_bal.key_send_accnt_bal_0_accnt_bal_egress_meta_recirculate);
                    }
                    if (send_accnt_bal.action_run == flow_def_send_accnt_bal_0__action_type_t.make_accnt_bal) {
                        angelic_assert(true);
                        if (hdr.lr_msg_type.isValid()) {
                            hdr.lr_msg_type.msg_type = 8w12;
                        }
                        else {
                            bug();
                        }
                        hdr.accnt_bal.setValid();
                        if (hdr.accnt_bal_req.isValid() && hdr.accnt_bal.isValid()) {
                            hdr.accnt_bal.time = hdr.accnt_bal_req.time;
                        }
                        else {
                            bug();
                        }
                        if (hdr.accnt_bal_req.isValid() && hdr.accnt_bal.isValid()) {
                            hdr.accnt_bal.vid = hdr.accnt_bal_req.vid;
                        }
                        else {
                            bug();
                        }
                        if (hdr.accnt_bal_req.isValid() && hdr.accnt_bal.isValid()) {
                            hdr.accnt_bal.qid = hdr.accnt_bal_req.qid;
                        }
                        else {
                            bug();
                        }
                        if (hdr.accnt_bal.isValid()) {
                            hdr.accnt_bal.bal = meta._toll_meta_bal38;
                        }
                        else {
                            bug();
                        }
                        hdr.accnt_bal_req.setInvalid();
                        if (hdr.ipv4.isValid()) {
                            hdr.ipv4.totalLen = 16w45;
                        }
                        else {
                            bug();
                        }
                        if (hdr.udp.isValid()) {
                            hdr.udp.length_ = 16w25;
                        }
                        else {
                            bug();
                        }
                        if (hdr.udp.isValid()) {
                            hdr.udp.checksum = 16w0;
                        }
                        else {
                            bug();
                        }
                    }
                    else {
                        if (send_accnt_bal.action_run == flow_def_send_accnt_bal_0__action_type_t.accnt_bal_e2e) {
                            angelic_assert(true);
                            meta._accnt_bal_egress_meta_recirculate5 = 1w1;
                            standard_metadata.clone_spec = 32w131072 | send_accnt_bal.accnt_bal_e2e__mir_ses;
                        }
                        else {
                            ;
                        }
                    }
                    end_send_accnt_bal_0();
                }
                else {
                    if (hdr.expenditure_req.isValid()) {
                        tmp_26 = query_daily_expenditure_0(hdr.expenditure_req.vid, hdr.expenditure_req.day, hdr.expenditure_req.xway);
                        daily_expenditure = tmp_26;
                        if (daily_expenditure.hit) {
                            key_match(hdr.expenditure_req.vid == daily_expenditure.key_daily_expenditure_0_expenditure_req_vid && hdr.expenditure_req.day == daily_expenditure.key_daily_expenditure_0_expenditure_req_day && hdr.expenditure_req.xway == daily_expenditure.key_daily_expenditure_0_expenditure_req_xway);
                            if (!hdr.expenditure_req.isValid()) {
                                bug();
                            }
                            if (!hdr.expenditure_req.isValid()) {
                                bug();
                            }
                            if (!hdr.expenditure_req.isValid()) {
                                bug();
                            }
                        }
                        if (daily_expenditure.action_run == flow_def_daily_expenditure_0__action_type_t.NoAction_0) {
                            ;
                        }
                        else {
                            if (daily_expenditure.action_run == flow_def_daily_expenditure_0__action_type_t.make_expenditure_report) {
                                angelic_assert(true);
                                if (hdr.lr_msg_type.isValid()) {
                                    hdr.lr_msg_type.msg_type = 8w13;
                                }
                                else {
                                    bug();
                                }
                                hdr.expenditure_report.setValid();
                                if (hdr.expenditure_req.isValid() && hdr.expenditure_report.isValid()) {
                                    hdr.expenditure_report.time = hdr.expenditure_req.time;
                                }
                                else {
                                    bug();
                                }
                                if (hdr.expenditure_req.isValid() && hdr.expenditure_report.isValid()) {
                                    hdr.expenditure_report.emit = hdr.expenditure_req.time;
                                }
                                else {
                                    bug();
                                }
                                if (hdr.expenditure_req.isValid() && hdr.expenditure_report.isValid()) {
                                    hdr.expenditure_report.qid = hdr.expenditure_req.qid;
                                }
                                else {
                                    bug();
                                }
                                if (hdr.expenditure_report.isValid()) {
                                    hdr.expenditure_report.bal = daily_expenditure.make_expenditure_report__bal;
                                }
                                else {
                                    bug();
                                }
                                hdr.expenditure_req.setInvalid();
                                if (hdr.ipv4.isValid()) {
                                    hdr.ipv4.totalLen = 16w39;
                                }
                                else {
                                    bug();
                                }
                                if (hdr.udp.isValid()) {
                                    hdr.udp.length_ = 16w19;
                                }
                                else {
                                    bug();
                                }
                                if (hdr.udp.isValid()) {
                                    hdr.udp.checksum = 16w0;
                                }
                                else {
                                    bug();
                                }
                            }
                            else {
                                ;
                            }
                        }
                        end_daily_expenditure_0();
                    }
                    else {
                        if (hdr.travel_estimate_req.isValid()) {
                            if (meta._te_md_recirculated29 == 1w0) {
                                if (hdr.travel_estimate_req.isValid() && hdr.travel_estimate_req.isValid()) {
                                    if (hdr.travel_estimate_req.seg_init < hdr.travel_estimate_req.seg_end) {
                                        tmp_27 = query_travel_estimate_init_0();
                                        travel_estimate_init = tmp_27;
                                        if (travel_estimate_init.action_run == flow_def_travel_estimate_init_0__action_type_t.do_travel_estimate_init) {
                                            angelic_assert(true);
                                            meta._te_md_dir30 = 1w0;
                                            if (hdr.travel_estimate_req.isValid()) {
                                                meta._te_md_seg_cur31 = hdr.travel_estimate_req.seg_init;
                                            }
                                            else {
                                                bug();
                                            }
                                            if (hdr.travel_estimate_req.isValid()) {
                                                meta._te_md_seg_end32 = hdr.travel_estimate_req.seg_end;
                                            }
                                            else {
                                                bug();
                                            }
                                        }
                                        else {
                                            ;
                                        }
                                        end_travel_estimate_init_0();
                                    }
                                    else {
                                        tmp_28 = query_travel_estimate_init_rev_0();
                                        travel_estimate_init_rev = tmp_28;
                                        if (travel_estimate_init_rev.action_run == flow_def_travel_estimate_init_rev_0__action_type_t.do_travel_estimate_init_rev) {
                                            angelic_assert(true);
                                            meta._te_md_dir30 = 1w1;
                                            if (hdr.travel_estimate_req.isValid()) {
                                                meta._te_md_seg_cur31 = hdr.travel_estimate_req.seg_end;
                                            }
                                            else {
                                                bug();
                                            }
                                            if (hdr.travel_estimate_req.isValid()) {
                                                meta._te_md_seg_end32 = hdr.travel_estimate_req.seg_init;
                                            }
                                            else {
                                                bug();
                                            }
                                        }
                                        else {
                                            ;
                                        }
                                        end_travel_estimate_init_rev_0();
                                    }
                                }
                                else {
                                    bug();
                                }
                            }
                            tmp_29 = query_travel_estimate_history_0(hdr.travel_estimate_req.dow, hdr.travel_estimate_req.tod, hdr.travel_estimate_req.xway, meta._te_md_dir30, meta._te_md_seg_cur31);
                            travel_estimate_history = tmp_29;
                            if (travel_estimate_history.hit) {
                                key_match(hdr.travel_estimate_req.dow == travel_estimate_history.key_travel_estimate_history_0_travel_estimate_req_dow && hdr.travel_estimate_req.tod == travel_estimate_history.key_travel_estimate_history_0_travel_estimate_req_tod && hdr.travel_estimate_req.xway == travel_estimate_history.key_travel_estimate_history_0_travel_estimate_req_xway && meta._te_md_dir30 == travel_estimate_history.key_travel_estimate_history_0_te_md_dir && meta._te_md_seg_cur31 == travel_estimate_history.key_travel_estimate_history_0_te_md_seg_cur);
                                if (!hdr.travel_estimate_req.isValid()) {
                                    bug();
                                }
                                if (!hdr.travel_estimate_req.isValid()) {
                                    bug();
                                }
                                if (!hdr.travel_estimate_req.isValid()) {
                                    bug();
                                }
                            }
                            if (travel_estimate_history.action_run == flow_def_travel_estimate_history_0__action_type_t.NoAction_25) {
                                ;
                            }
                            else {
                                if (travel_estimate_history.action_run == flow_def_travel_estimate_history_0__action_type_t.update_travel_estimate) {
                                    angelic_assert(true);
                                    meta._te_md_time_sum34 = meta._te_md_time_sum34 + travel_estimate_history.update_travel_estimate__time;
                                    meta._te_md_toll_sum33 = meta._te_md_toll_sum33 + travel_estimate_history.update_travel_estimate__toll;
                                }
                                else {
                                    ;
                                }
                            }
                            end_travel_estimate_history_0();
                            if (meta._te_md_seg_cur31 == meta._te_md_seg_end32) {
                                tmp_30 = query_travel_estimate_send_0();
                                travel_estimate_send = tmp_30;
                                if (travel_estimate_send.action_run == flow_def_travel_estimate_send_0__action_type_t.do_travel_estimate_send) {
                                    angelic_assert(true);
                                    if (hdr.lr_msg_type.isValid()) {
                                        hdr.lr_msg_type.msg_type = 8w14;
                                    }
                                    else {
                                        bug();
                                    }
                                    hdr.travel_estimate.setValid();
                                    if (hdr.travel_estimate_req.isValid() && hdr.travel_estimate.isValid()) {
                                        hdr.travel_estimate.qid = hdr.travel_estimate_req.qid;
                                    }
                                    else {
                                        bug();
                                    }
                                    if (hdr.travel_estimate.isValid()) {
                                        hdr.travel_estimate.travel_time = meta._te_md_time_sum34;
                                    }
                                    else {
                                        bug();
                                    }
                                    if (hdr.travel_estimate.isValid()) {
                                        hdr.travel_estimate.toll = meta._te_md_toll_sum33;
                                    }
                                    else {
                                        bug();
                                    }
                                    hdr.travel_estimate_req.setInvalid();
                                    if (hdr.ipv4.isValid()) {
                                        hdr.ipv4.totalLen = 16w37;
                                    }
                                    else {
                                        bug();
                                    }
                                    if (hdr.udp.isValid()) {
                                        hdr.udp.length_ = 16w17;
                                    }
                                    else {
                                        bug();
                                    }
                                    if (hdr.udp.isValid()) {
                                        hdr.udp.checksum = 16w0;
                                    }
                                    else {
                                        bug();
                                    }
                                }
                                else {
                                    ;
                                }
                                end_travel_estimate_send_0();
                            }
                            else {
                                tmp_31 = query_travel_estimate_recirc_0();
                                travel_estimate_recirc = tmp_31;
                                if (travel_estimate_recirc.action_run == flow_def_travel_estimate_recirc_0__action_type_t.travel_estimate_e2e) {
                                    angelic_assert(true);
                                    meta._te_md_seg_cur31 = meta._te_md_seg_cur31 + 8w1;
                                    meta._te_md_recirculated29 = 1w1;
                                    standard_metadata.clone_spec = 32w262144 | travel_estimate_recirc.travel_estimate_e2e__mir_ses;
                                    standard_metadata.egress_spec = 9w511;
                                }
                                else {
                                    ;
                                }
                                end_travel_estimate_recirc_0();
                            }
                        }
                    }
                }
            }
            tmp_32 = query_send_frame_0(standard_metadata.egress_port);
            send_frame = tmp_32;
            if (send_frame.hit) {
                key_match(standard_metadata.egress_port == send_frame.key_send_frame_0_standard_metadata_egress_port);
            }
            if (send_frame.action_run == flow_def_send_frame_0__action_type_t.NoAction_23) {
                ;
            }
            else {
                if (send_frame.action_run == flow_def_send_frame_0__action_type_t._drop) {
                    angelic_assert(true);
                    standard_metadata.egress_spec = 9w511;
                }
                else {
                    if (send_frame.action_run == flow_def_send_frame_0__action_type_t.rewrite_mac) {
                        angelic_assert(true);
                        if (hdr.ethernet.isValid()) {
                            hdr.ethernet.srcAddr = send_frame.rewrite_mac__smac;
                        }
                        else {
                            bug();
                        }
                    }
                    else {
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
    flow_def_update_pos_state_0 update_pos_state;
    flow_def_update_new_seg_0 update_new_seg;
    flow_def_update_vol_state_0 update_vol_state;
    flow_def_update_ewma_spd_0 update_ewma_spd;
    flow_def_loc_not_changed_0 loc_not_changed;
    flow_def_loc_changed_0 loc_changed;
    flow_def_dec_prev_stopped_0 dec_prev_stopped;
    flow_def_inc_stopped_0 inc_stopped;
    flow_def_load_stopped_ahead_0 load_stopped_ahead;
    flow_def_check_accidents_0 check_accidents;
    flow_def_check_toll_0 check_toll;
    flow_def_load_accnt_bal_0 load_accnt_bal;
    flow_def_ipv4_lpm_0 ipv4_lpm;
    flow_def_forward_0 forward;
    flow_def_update_pos_state_0 tmp_33;
    flow_def_update_new_seg_0 tmp_34;
    flow_def_update_vol_state_0 tmp_35;
    flow_def_update_ewma_spd_0 tmp_36;
    flow_def_loc_not_changed_0 tmp_37;
    flow_def_loc_changed_0 tmp_38;
    flow_def_dec_prev_stopped_0 tmp_39;
    flow_def_inc_stopped_0 tmp_40;
    flow_def_load_stopped_ahead_0 tmp_41;
    flow_def_check_accidents_0 tmp_42;
    flow_def_check_toll_0 tmp_43;
    flow_def_load_accnt_bal_0 tmp_44;
    flow_def_ipv4_lpm_0 tmp_45;
    flow_def_forward_0 tmp_46;
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
                tmp_33 = query_update_pos_state_0();
                update_pos_state = tmp_33;
                if (update_pos_state.action_run == flow_def_update_pos_state_0__action_type_t.do_update_pos_state) {
                    angelic_assert(true);
                    if (hdr.pos_report.isValid()) {
                        if (hdr.pos_report.vid >= 32w512) {
                            bug();
                        }
                        v_valid_reg_0.read(meta._v_state_new39, hdr.pos_report.vid);
                    }
                    else {
                        bug();
                    }
                    meta._v_state_new39 = ~meta._v_state_new39;
                    if (hdr.pos_report.isValid()) {
                        if (hdr.pos_report.vid >= 32w512) {
                            bug();
                        }
                        v_spd_reg_0.read(meta._v_state_prev_spd41, hdr.pos_report.vid);
                    }
                    else {
                        bug();
                    }
                    if (hdr.pos_report.isValid()) {
                        if (hdr.pos_report.vid >= 32w512) {
                            bug();
                        }
                        v_xway_reg_0.read(meta._v_state_prev_xway42, hdr.pos_report.vid);
                    }
                    else {
                        bug();
                    }
                    if (hdr.pos_report.isValid()) {
                        if (hdr.pos_report.vid >= 32w512) {
                            bug();
                        }
                        v_lane_reg_0.read(meta._v_state_prev_lane43, hdr.pos_report.vid);
                    }
                    else {
                        bug();
                    }
                    if (hdr.pos_report.isValid()) {
                        if (hdr.pos_report.vid >= 32w512) {
                            bug();
                        }
                        v_seg_reg_0.read(meta._v_state_prev_seg44, hdr.pos_report.vid);
                    }
                    else {
                        bug();
                    }
                    if (hdr.pos_report.isValid()) {
                        if (hdr.pos_report.vid >= 32w512) {
                            bug();
                        }
                        v_dir_reg_0.read(meta._v_state_prev_dir45, hdr.pos_report.vid);
                    }
                    else {
                        bug();
                    }
                    if (hdr.pos_report.isValid()) {
                        if (hdr.pos_report.vid >= 32w512) {
                            bug();
                        }
                        v_valid_reg_0.write(hdr.pos_report.vid, 1w1);
                    }
                    else {
                        bug();
                    }
                    if (hdr.pos_report.isValid() && hdr.pos_report.isValid()) {
                        if (hdr.pos_report.vid >= 32w512) {
                            bug();
                        }
                        v_spd_reg_0.write(hdr.pos_report.vid, hdr.pos_report.spd);
                    }
                    else {
                        bug();
                    }
                    if (hdr.pos_report.isValid() && hdr.pos_report.isValid()) {
                        if (hdr.pos_report.vid >= 32w512) {
                            bug();
                        }
                        v_xway_reg_0.write(hdr.pos_report.vid, hdr.pos_report.xway);
                    }
                    else {
                        bug();
                    }
                    if (hdr.pos_report.isValid() && hdr.pos_report.isValid()) {
                        if (hdr.pos_report.vid >= 32w512) {
                            bug();
                        }
                        v_lane_reg_0.write(hdr.pos_report.vid, (bit<3>)hdr.pos_report.lane);
                    }
                    else {
                        bug();
                    }
                    if (hdr.pos_report.isValid() && hdr.pos_report.isValid()) {
                        if (hdr.pos_report.vid >= 32w512) {
                            bug();
                        }
                        v_seg_reg_0.write(hdr.pos_report.vid, hdr.pos_report.seg);
                    }
                    else {
                        bug();
                    }
                    if (hdr.pos_report.isValid() && hdr.pos_report.isValid()) {
                        if (hdr.pos_report.vid >= 32w512) {
                            bug();
                        }
                        v_dir_reg_0.write(hdr.pos_report.vid, (bit<1>)hdr.pos_report.dir);
                    }
                    else {
                        bug();
                    }
                }
                else {
                    ;
                }
                end_update_pos_state_0();
                if (hdr.pos_report.isValid() || meta._v_state_new39 == 1w1) {
                    if (meta._v_state_new39 == 1w1 || meta._v_state_prev_seg44 != hdr.pos_report.seg) {
                        tmp_34 = query_update_new_seg_0();
                        update_new_seg = tmp_34;
                        if (update_new_seg.action_run == flow_def_update_new_seg_0__action_type_t.set_new_seg) {
                            angelic_assert(true);
                            meta._v_state_new_seg40 = 1w1;
                        }
                        else {
                            ;
                        }
                        end_update_new_seg_0();
                    }
                }
                else {
                    bug();
                }
                tmp_35 = query_update_vol_state_0(meta._v_state_new39, meta._v_state_new_seg40);
                update_vol_state = tmp_35;
                if (update_vol_state.hit) {
                    key_match(meta._v_state_new39 == update_vol_state.key_update_vol_state_0_v_state_new && meta._v_state_new_seg40 == update_vol_state.key_update_vol_state_0_v_state_new_seg);
                }
                if (update_vol_state.action_run == flow_def_update_vol_state_0__action_type_t.load_and_inc_and_dec_vol) {
                    angelic_assert(true);
                    if (hdr.pos_report.isValid() && hdr.pos_report.isValid() && hdr.pos_report.isValid()) {
                        if ((bit<32>)((bit<16>)hdr.pos_report.xway * 16w200 + (bit<16>)(hdr.pos_report.seg << 1) + (bit<16>)hdr.pos_report.dir) >= 32w400) {
                            bug();
                        }
                        seg_vol_reg_0.read(meta._seg_meta_vol6, (bit<32>)((bit<16>)hdr.pos_report.xway * 16w200 + (bit<16>)(hdr.pos_report.seg << 1) + (bit<16>)hdr.pos_report.dir));
                    }
                    else {
                        bug();
                    }
                    meta._seg_meta_vol6 = meta._seg_meta_vol6 + 8w1;
                    if (hdr.pos_report.isValid() && hdr.pos_report.isValid() && hdr.pos_report.isValid()) {
                        if ((bit<32>)((bit<16>)hdr.pos_report.xway * 16w200 + (bit<16>)(hdr.pos_report.seg << 1) + (bit<16>)hdr.pos_report.dir) >= 32w400) {
                            bug();
                        }
                        seg_vol_reg_0.write((bit<32>)((bit<16>)hdr.pos_report.xway * 16w200 + (bit<16>)(hdr.pos_report.seg << 1) + (bit<16>)hdr.pos_report.dir), meta._seg_meta_vol6);
                    }
                    else {
                        bug();
                    }
                    if ((bit<32>)((bit<16>)meta._v_state_prev_xway42 * 16w200 + (bit<16>)(meta._v_state_prev_seg44 << 1) + (bit<16>)meta._v_state_prev_dir45) >= 32w400) {
                        bug();
                    }
                    seg_vol_reg_0.read(meta._seg_meta_prev_vol7, (bit<32>)((bit<16>)meta._v_state_prev_xway42 * 16w200 + (bit<16>)(meta._v_state_prev_seg44 << 1) + (bit<16>)meta._v_state_prev_dir45));
                    meta._seg_meta_prev_vol7 = meta._seg_meta_prev_vol7 + 8w255;
                    if ((bit<32>)((bit<16>)meta._v_state_prev_xway42 * 16w200 + (bit<16>)(meta._v_state_prev_seg44 << 1) + (bit<16>)meta._v_state_prev_dir45) >= 32w400) {
                        bug();
                    }
                    seg_vol_reg_0.write((bit<32>)((bit<16>)meta._v_state_prev_xway42 * 16w200 + (bit<16>)(meta._v_state_prev_seg44 << 1) + (bit<16>)meta._v_state_prev_dir45), meta._seg_meta_prev_vol7);
                }
                else {
                    if (update_vol_state.action_run == flow_def_update_vol_state_0__action_type_t.load_and_inc_vol) {
                        angelic_assert(true);
                        if (hdr.pos_report.isValid() && hdr.pos_report.isValid() && hdr.pos_report.isValid()) {
                            if ((bit<32>)((bit<16>)hdr.pos_report.xway * 16w200 + (bit<16>)(hdr.pos_report.seg << 1) + (bit<16>)hdr.pos_report.dir) >= 32w400) {
                                bug();
                            }
                            seg_vol_reg_0.read(meta._seg_meta_vol6, (bit<32>)((bit<16>)hdr.pos_report.xway * 16w200 + (bit<16>)(hdr.pos_report.seg << 1) + (bit<16>)hdr.pos_report.dir));
                        }
                        else {
                            bug();
                        }
                        meta._seg_meta_vol6 = meta._seg_meta_vol6 + 8w1;
                        if (hdr.pos_report.isValid() && hdr.pos_report.isValid() && hdr.pos_report.isValid()) {
                            if ((bit<32>)((bit<16>)hdr.pos_report.xway * 16w200 + (bit<16>)(hdr.pos_report.seg << 1) + (bit<16>)hdr.pos_report.dir) >= 32w400) {
                                bug();
                            }
                            seg_vol_reg_0.write((bit<32>)((bit<16>)hdr.pos_report.xway * 16w200 + (bit<16>)(hdr.pos_report.seg << 1) + (bit<16>)hdr.pos_report.dir), meta._seg_meta_vol6);
                        }
                        else {
                            bug();
                        }
                    }
                    else {
                        if (update_vol_state.action_run == flow_def_update_vol_state_0__action_type_t.load_vol) {
                            angelic_assert(true);
                            if (hdr.pos_report.isValid() && hdr.pos_report.isValid() && hdr.pos_report.isValid()) {
                                if ((bit<32>)((bit<16>)hdr.pos_report.xway * 16w200 + (bit<16>)(hdr.pos_report.seg << 1) + (bit<16>)hdr.pos_report.dir) >= 32w400) {
                                    bug();
                                }
                                seg_vol_reg_0.read(meta._seg_meta_vol6, (bit<32>)((bit<16>)hdr.pos_report.xway * 16w200 + (bit<16>)(hdr.pos_report.seg << 1) + (bit<16>)hdr.pos_report.dir));
                            }
                            else {
                                bug();
                            }
                        }
                        else {
                            ;
                        }
                    }
                }
                end_update_vol_state_0();
                tmp_36 = query_update_ewma_spd_0(meta._seg_meta_vol6);
                update_ewma_spd = tmp_36;
                if (update_ewma_spd.hit) {
                    key_match(meta._seg_meta_vol6 == update_ewma_spd.key_update_ewma_spd_0_seg_meta_vol);
                }
                if (update_ewma_spd.action_run == flow_def_update_ewma_spd_0__action_type_t.calc_ewma_spd) {
                    angelic_assert(true);
                    if (hdr.pos_report.isValid() && hdr.pos_report.isValid() && hdr.pos_report.isValid()) {
                        if ((bit<32>)((bit<16>)hdr.pos_report.xway * 16w200 + (bit<16>)(hdr.pos_report.seg << 1) + (bit<16>)hdr.pos_report.dir) >= 32w400) {
                            bug();
                        }
                        seg_ewma_spd_reg_0.read(meta._seg_meta_ewma_spd8, (bit<32>)((bit<16>)hdr.pos_report.xway * 16w200 + (bit<16>)(hdr.pos_report.seg << 1) + (bit<16>)hdr.pos_report.dir));
                    }
                    else {
                        bug();
                    }
                    meta._seg_meta_ewma_spd8 = (bit<16>)((bit<32>)meta._seg_meta_ewma_spd8 * 32w96 + (bit<32>)((bit<16>)hdr.pos_report.spd << 5) >> 7);
                    if (hdr.pos_report.isValid() && hdr.pos_report.isValid() && hdr.pos_report.isValid()) {
                        if ((bit<32>)((bit<16>)hdr.pos_report.xway * 16w200 + (bit<16>)(hdr.pos_report.seg << 1) + (bit<16>)hdr.pos_report.dir) >= 32w400) {
                            bug();
                        }
                        seg_ewma_spd_reg_0.write((bit<32>)((bit<16>)hdr.pos_report.xway * 16w200 + (bit<16>)(hdr.pos_report.seg << 1) + (bit<16>)hdr.pos_report.dir), meta._seg_meta_ewma_spd8);
                    }
                    else {
                        bug();
                    }
                }
                else {
                    if (update_ewma_spd.action_run == flow_def_update_ewma_spd_0__action_type_t.set_spd) {
                        angelic_assert(true);
                        if (hdr.pos_report.isValid()) {
                            meta._seg_meta_ewma_spd8 = (bit<16>)hdr.pos_report.spd;
                        }
                        else {
                            bug();
                        }
                        if (hdr.pos_report.isValid() && (hdr.pos_report.isValid() && hdr.pos_report.isValid() && hdr.pos_report.isValid())) {
                            if ((bit<32>)((bit<16>)hdr.pos_report.xway * 16w200 + (bit<16>)(hdr.pos_report.seg << 1) + (bit<16>)hdr.pos_report.dir) >= 32w400) {
                                bug();
                            }
                            seg_ewma_spd_reg_0.write((bit<32>)((bit<16>)hdr.pos_report.xway * 16w200 + (bit<16>)(hdr.pos_report.seg << 1) + (bit<16>)hdr.pos_report.dir), (bit<16>)hdr.pos_report.spd);
                        }
                        else {
                            bug();
                        }
                    }
                    else {
                        ;
                    }
                }
                end_update_ewma_spd_0();
                if (((hdr.pos_report.isValid() && hdr.pos_report.isValid() || hdr.pos_report.isValid() && hdr.pos_report.xway != meta._v_state_prev_xway42 || hdr.pos_report.isValid() && hdr.pos_report.seg != meta._v_state_prev_seg44) && hdr.pos_report.isValid() || (hdr.pos_report.isValid() && hdr.pos_report.isValid() || hdr.pos_report.isValid() && hdr.pos_report.xway != meta._v_state_prev_xway42 || hdr.pos_report.isValid() && hdr.pos_report.seg != meta._v_state_prev_seg44) && !(hdr.pos_report.xway == meta._v_state_prev_xway42 && hdr.pos_report.seg == meta._v_state_prev_seg44) || hdr.pos_report.isValid() && hdr.pos_report.dir != (bit<8>)meta._v_state_prev_dir45) && hdr.pos_report.isValid() || ((hdr.pos_report.isValid() && hdr.pos_report.isValid() || hdr.pos_report.isValid() && hdr.pos_report.xway != meta._v_state_prev_xway42 || hdr.pos_report.isValid() && hdr.pos_report.seg != meta._v_state_prev_seg44) && hdr.pos_report.isValid() || (hdr.pos_report.isValid() && hdr.pos_report.isValid() || hdr.pos_report.isValid() && hdr.pos_report.xway != meta._v_state_prev_xway42 || hdr.pos_report.isValid() && hdr.pos_report.seg != meta._v_state_prev_seg44) && !(hdr.pos_report.xway == meta._v_state_prev_xway42 && hdr.pos_report.seg == meta._v_state_prev_seg44) || hdr.pos_report.isValid() && hdr.pos_report.dir != (bit<8>)meta._v_state_prev_dir45) && !(hdr.pos_report.xway == meta._v_state_prev_xway42 && hdr.pos_report.seg == meta._v_state_prev_seg44 && hdr.pos_report.dir == (bit<8>)meta._v_state_prev_dir45) || hdr.pos_report.isValid() && hdr.pos_report.lane != (bit<8>)meta._v_state_prev_lane43) {
                    if (hdr.pos_report.xway == meta._v_state_prev_xway42 && hdr.pos_report.seg == meta._v_state_prev_seg44 && hdr.pos_report.dir == (bit<8>)meta._v_state_prev_dir45 && hdr.pos_report.lane == (bit<8>)meta._v_state_prev_lane43) {
                        tmp_37 = query_loc_not_changed_0();
                        loc_not_changed = tmp_37;
                        if (loc_not_changed.action_run == flow_def_loc_not_changed_0__action_type_t.do_loc_not_changed) {
                            angelic_assert(true);
                            if (hdr.pos_report.isValid()) {
                                if (hdr.pos_report.vid >= 32w512) {
                                    bug();
                                }
                                v_nomove_cnt_reg_0.read(meta._v_state_prev_nomove_cnt46, hdr.pos_report.vid);
                            }
                            else {
                                bug();
                            }
                            meta._v_state_nomove_cnt47 = meta._v_state_prev_nomove_cnt46 + 3w1 - ((meta._v_state_prev_nomove_cnt46 + 3w1 & 3w4) >> 2);
                            if (hdr.pos_report.isValid()) {
                                if (hdr.pos_report.vid >= 32w512) {
                                    bug();
                                }
                                v_nomove_cnt_reg_0.write(hdr.pos_report.vid, meta._v_state_prev_nomove_cnt46 + 3w1 - ((meta._v_state_prev_nomove_cnt46 + 3w1 & 3w4) >> 2));
                            }
                            else {
                                bug();
                            }
                        }
                        else {
                            ;
                        }
                        end_loc_not_changed_0();
                    }
                    else {
                        tmp_38 = query_loc_changed_0();
                        loc_changed = tmp_38;
                        if (loc_changed.action_run == flow_def_loc_changed_0__action_type_t.do_loc_changed) {
                            angelic_assert(true);
                            if (hdr.pos_report.isValid()) {
                                if (hdr.pos_report.vid >= 32w512) {
                                    bug();
                                }
                                v_nomove_cnt_reg_0.read(meta._v_state_prev_nomove_cnt46, hdr.pos_report.vid);
                            }
                            else {
                                bug();
                            }
                            if (hdr.pos_report.isValid()) {
                                if (hdr.pos_report.vid >= 32w512) {
                                    bug();
                                }
                                v_nomove_cnt_reg_0.write(hdr.pos_report.vid, 3w0);
                            }
                            else {
                                bug();
                            }
                        }
                        else {
                            ;
                        }
                        end_loc_changed_0();
                    }
                }
                else {
                    bug();
                }
                if (meta._v_state_prev_nomove_cnt46 == 3w3 && meta._v_state_nomove_cnt47 < 3w3) {
                    tmp_39 = query_dec_prev_stopped_0();
                    dec_prev_stopped = tmp_39;
                    if (dec_prev_stopped.action_run == flow_def_dec_prev_stopped_0__action_type_t.do_dec_prev_stopped) {
                        angelic_assert(true);
                        if ((bit<32>)((bit<16>)meta._v_state_prev_xway42 * 16w600 + (bit<16>)(meta._v_state_prev_seg44 << 1) * 16w3 + (bit<16>)meta._v_state_prev_dir45 * 16w3 + (bit<16>)meta._v_state_prev_lane43) >= 32w1200) {
                            bug();
                        }
                        stopped_cnt_reg_0.read(meta._accident_meta_prev_stp_cnt2, (bit<32>)((bit<16>)meta._v_state_prev_xway42 * 16w600 + (bit<16>)(meta._v_state_prev_seg44 << 1) * 16w3 + (bit<16>)meta._v_state_prev_dir45 * 16w3 + (bit<16>)meta._v_state_prev_lane43));
                        if ((bit<32>)((bit<16>)meta._v_state_prev_xway42 * 16w600 + (bit<16>)(meta._v_state_prev_seg44 << 1) * 16w3 + (bit<16>)meta._v_state_prev_dir45 * 16w3 + (bit<16>)meta._v_state_prev_lane43) >= 32w1200) {
                            bug();
                        }
                        stopped_cnt_reg_0.write((bit<32>)((bit<16>)meta._v_state_prev_xway42 * 16w600 + (bit<16>)(meta._v_state_prev_seg44 << 1) * 16w3 + (bit<16>)meta._v_state_prev_dir45 * 16w3 + (bit<16>)meta._v_state_prev_lane43), meta._accident_meta_prev_stp_cnt2 + 8w255);
                    }
                    else {
                        ;
                    }
                    end_dec_prev_stopped_0();
                }
                if (meta._v_state_prev_nomove_cnt46 < 3w3 && meta._v_state_nomove_cnt47 == 3w3) {
                    tmp_40 = query_inc_stopped_0();
                    inc_stopped = tmp_40;
                    if (inc_stopped.action_run == flow_def_inc_stopped_0__action_type_t.do_inc_stopped) {
                        angelic_assert(true);
                        if (hdr.pos_report.isValid() && hdr.pos_report.isValid() && hdr.pos_report.isValid() && hdr.pos_report.isValid()) {
                            if ((bit<32>)((bit<16>)hdr.pos_report.xway * 16w600 + (bit<16>)(hdr.pos_report.seg << 1) * 16w3 + (bit<16>)hdr.pos_report.dir * 16w3 + (bit<16>)hdr.pos_report.lane) >= 32w1200) {
                                bug();
                            }
                            stopped_cnt_reg_0.read(meta._accident_meta_cur_stp_cnt1, (bit<32>)((bit<16>)hdr.pos_report.xway * 16w600 + (bit<16>)(hdr.pos_report.seg << 1) * 16w3 + (bit<16>)hdr.pos_report.dir * 16w3 + (bit<16>)hdr.pos_report.lane));
                        }
                        else {
                            bug();
                        }
                        if (hdr.pos_report.isValid() && hdr.pos_report.isValid() && hdr.pos_report.isValid() && hdr.pos_report.isValid()) {
                            if ((bit<32>)((bit<16>)hdr.pos_report.xway * 16w600 + (bit<16>)(hdr.pos_report.seg << 1) * 16w3 + (bit<16>)hdr.pos_report.dir * 16w3 + (bit<16>)hdr.pos_report.lane) >= 32w1200) {
                                bug();
                            }
                            stopped_cnt_reg_0.write((bit<32>)((bit<16>)hdr.pos_report.xway * 16w600 + (bit<16>)(hdr.pos_report.seg << 1) * 16w3 + (bit<16>)hdr.pos_report.dir * 16w3 + (bit<16>)hdr.pos_report.lane), meta._accident_meta_cur_stp_cnt1 + 8w1);
                        }
                        else {
                            bug();
                        }
                    }
                    else {
                        ;
                    }
                    end_inc_stopped_0();
                }
                tmp_41 = query_load_stopped_ahead_0();
                load_stopped_ahead = tmp_41;
                if (load_stopped_ahead.action_run == flow_def_load_stopped_ahead_0__action_type_t.do_load_stopped_ahead) {
                    angelic_assert(true);
                    if (hdr.pos_report.isValid() && hdr.pos_report.isValid() && hdr.pos_report.isValid()) {
                        if ((bit<32>)((bit<16>)hdr.pos_report.xway * 16w600 + (bit<16>)(hdr.pos_report.seg << 1) * 16w3 + (bit<16>)hdr.pos_report.dir * 16w3 + 16w1) >= 32w1200) {
                            bug();
                        }
                        stopped_cnt_reg_0.read(meta._stopped_ahead_seg0l19, (bit<32>)((bit<16>)hdr.pos_report.xway * 16w600 + (bit<16>)(hdr.pos_report.seg << 1) * 16w3 + (bit<16>)hdr.pos_report.dir * 16w3 + 16w1));
                    }
                    else {
                        bug();
                    }
                    if (hdr.pos_report.isValid() && hdr.pos_report.isValid() && hdr.pos_report.isValid()) {
                        if ((bit<32>)((bit<16>)hdr.pos_report.xway * 16w600 + (bit<16>)(hdr.pos_report.seg << 1) * 16w3 + (bit<16>)hdr.pos_report.dir * 16w3 + 16w2) >= 32w1200) {
                            bug();
                        }
                        stopped_cnt_reg_0.read(meta._stopped_ahead_seg0l210, (bit<32>)((bit<16>)hdr.pos_report.xway * 16w600 + (bit<16>)(hdr.pos_report.seg << 1) * 16w3 + (bit<16>)hdr.pos_report.dir * 16w3 + 16w2));
                    }
                    else {
                        bug();
                    }
                    if (hdr.pos_report.isValid() && hdr.pos_report.isValid() && hdr.pos_report.isValid()) {
                        if ((bit<32>)((bit<16>)hdr.pos_report.xway * 16w600 + (bit<16>)(hdr.pos_report.seg << 1) * 16w3 + (bit<16>)hdr.pos_report.dir * 16w3 + 16w3) >= 32w1200) {
                            bug();
                        }
                        stopped_cnt_reg_0.read(meta._stopped_ahead_seg0l311, (bit<32>)((bit<16>)hdr.pos_report.xway * 16w600 + (bit<16>)(hdr.pos_report.seg << 1) * 16w3 + (bit<16>)hdr.pos_report.dir * 16w3 + 16w3));
                    }
                    else {
                        bug();
                    }
                    if (hdr.pos_report.isValid() && hdr.pos_report.isValid() && hdr.pos_report.isValid()) {
                        if ((bit<32>)((bit<16>)hdr.pos_report.xway * 16w600 + (bit<16>)(hdr.pos_report.seg + 8w1 << 1) * 16w3 + (bit<16>)hdr.pos_report.dir * 16w3 + 16w1) >= 32w1200) {
                            bug();
                        }
                        stopped_cnt_reg_0.read(meta._stopped_ahead_seg1l112, (bit<32>)((bit<16>)hdr.pos_report.xway * 16w600 + (bit<16>)(hdr.pos_report.seg + 8w1 << 1) * 16w3 + (bit<16>)hdr.pos_report.dir * 16w3 + 16w1));
                    }
                    else {
                        bug();
                    }
                    if (hdr.pos_report.isValid() && hdr.pos_report.isValid() && hdr.pos_report.isValid()) {
                        if ((bit<32>)((bit<16>)hdr.pos_report.xway * 16w600 + (bit<16>)(hdr.pos_report.seg + 8w1 << 1) * 16w3 + (bit<16>)hdr.pos_report.dir * 16w3 + 16w2) >= 32w1200) {
                            bug();
                        }
                        stopped_cnt_reg_0.read(meta._stopped_ahead_seg1l213, (bit<32>)((bit<16>)hdr.pos_report.xway * 16w600 + (bit<16>)(hdr.pos_report.seg + 8w1 << 1) * 16w3 + (bit<16>)hdr.pos_report.dir * 16w3 + 16w2));
                    }
                    else {
                        bug();
                    }
                    if (hdr.pos_report.isValid() && hdr.pos_report.isValid() && hdr.pos_report.isValid()) {
                        if ((bit<32>)((bit<16>)hdr.pos_report.xway * 16w600 + (bit<16>)(hdr.pos_report.seg + 8w1 << 1) * 16w3 + (bit<16>)hdr.pos_report.dir * 16w3 + 16w3) >= 32w1200) {
                            bug();
                        }
                        stopped_cnt_reg_0.read(meta._stopped_ahead_seg1l314, (bit<32>)((bit<16>)hdr.pos_report.xway * 16w600 + (bit<16>)(hdr.pos_report.seg + 8w1 << 1) * 16w3 + (bit<16>)hdr.pos_report.dir * 16w3 + 16w3));
                    }
                    else {
                        bug();
                    }
                    if (hdr.pos_report.isValid() && hdr.pos_report.isValid() && hdr.pos_report.isValid()) {
                        if ((bit<32>)((bit<16>)hdr.pos_report.xway * 16w600 + (bit<16>)(hdr.pos_report.seg + 8w2 << 1) * 16w3 + (bit<16>)hdr.pos_report.dir * 16w3 + 16w1) >= 32w1200) {
                            bug();
                        }
                        stopped_cnt_reg_0.read(meta._stopped_ahead_seg2l115, (bit<32>)((bit<16>)hdr.pos_report.xway * 16w600 + (bit<16>)(hdr.pos_report.seg + 8w2 << 1) * 16w3 + (bit<16>)hdr.pos_report.dir * 16w3 + 16w1));
                    }
                    else {
                        bug();
                    }
                    if (hdr.pos_report.isValid() && hdr.pos_report.isValid() && hdr.pos_report.isValid()) {
                        if ((bit<32>)((bit<16>)hdr.pos_report.xway * 16w600 + (bit<16>)(hdr.pos_report.seg + 8w2 << 1) * 16w3 + (bit<16>)hdr.pos_report.dir * 16w3 + 16w2) >= 32w1200) {
                            bug();
                        }
                        stopped_cnt_reg_0.read(meta._stopped_ahead_seg2l216, (bit<32>)((bit<16>)hdr.pos_report.xway * 16w600 + (bit<16>)(hdr.pos_report.seg + 8w2 << 1) * 16w3 + (bit<16>)hdr.pos_report.dir * 16w3 + 16w2));
                    }
                    else {
                        bug();
                    }
                    if (hdr.pos_report.isValid() && hdr.pos_report.isValid() && hdr.pos_report.isValid()) {
                        if ((bit<32>)((bit<16>)hdr.pos_report.xway * 16w600 + (bit<16>)(hdr.pos_report.seg + 8w2 << 1) * 16w3 + (bit<16>)hdr.pos_report.dir * 16w3 + 16w3) >= 32w1200) {
                            bug();
                        }
                        stopped_cnt_reg_0.read(meta._stopped_ahead_seg2l317, (bit<32>)((bit<16>)hdr.pos_report.xway * 16w600 + (bit<16>)(hdr.pos_report.seg + 8w2 << 1) * 16w3 + (bit<16>)hdr.pos_report.dir * 16w3 + 16w3));
                    }
                    else {
                        bug();
                    }
                    if (hdr.pos_report.isValid() && hdr.pos_report.isValid() && hdr.pos_report.isValid()) {
                        if ((bit<32>)((bit<16>)hdr.pos_report.xway * 16w600 + (bit<16>)(hdr.pos_report.seg + 8w3 << 1) * 16w3 + (bit<16>)hdr.pos_report.dir * 16w3 + 16w1) >= 32w1200) {
                            bug();
                        }
                        stopped_cnt_reg_0.read(meta._stopped_ahead_seg3l118, (bit<32>)((bit<16>)hdr.pos_report.xway * 16w600 + (bit<16>)(hdr.pos_report.seg + 8w3 << 1) * 16w3 + (bit<16>)hdr.pos_report.dir * 16w3 + 16w1));
                    }
                    else {
                        bug();
                    }
                    if (hdr.pos_report.isValid() && hdr.pos_report.isValid() && hdr.pos_report.isValid()) {
                        if ((bit<32>)((bit<16>)hdr.pos_report.xway * 16w600 + (bit<16>)(hdr.pos_report.seg + 8w3 << 1) * 16w3 + (bit<16>)hdr.pos_report.dir * 16w3 + 16w2) >= 32w1200) {
                            bug();
                        }
                        stopped_cnt_reg_0.read(meta._stopped_ahead_seg3l219, (bit<32>)((bit<16>)hdr.pos_report.xway * 16w600 + (bit<16>)(hdr.pos_report.seg + 8w3 << 1) * 16w3 + (bit<16>)hdr.pos_report.dir * 16w3 + 16w2));
                    }
                    else {
                        bug();
                    }
                    if (hdr.pos_report.isValid() && hdr.pos_report.isValid() && hdr.pos_report.isValid()) {
                        if ((bit<32>)((bit<16>)hdr.pos_report.xway * 16w600 + (bit<16>)(hdr.pos_report.seg + 8w3 << 1) * 16w3 + (bit<16>)hdr.pos_report.dir * 16w3 + 16w3) >= 32w1200) {
                            bug();
                        }
                        stopped_cnt_reg_0.read(meta._stopped_ahead_seg3l320, (bit<32>)((bit<16>)hdr.pos_report.xway * 16w600 + (bit<16>)(hdr.pos_report.seg + 8w3 << 1) * 16w3 + (bit<16>)hdr.pos_report.dir * 16w3 + 16w3));
                    }
                    else {
                        bug();
                    }
                    if (hdr.pos_report.isValid() && hdr.pos_report.isValid() && hdr.pos_report.isValid()) {
                        if ((bit<32>)((bit<16>)hdr.pos_report.xway * 16w600 + (bit<16>)(hdr.pos_report.seg + 8w4 << 1) * 16w3 + (bit<16>)hdr.pos_report.dir * 16w3 + 16w1) >= 32w1200) {
                            bug();
                        }
                        stopped_cnt_reg_0.read(meta._stopped_ahead_seg4l121, (bit<32>)((bit<16>)hdr.pos_report.xway * 16w600 + (bit<16>)(hdr.pos_report.seg + 8w4 << 1) * 16w3 + (bit<16>)hdr.pos_report.dir * 16w3 + 16w1));
                    }
                    else {
                        bug();
                    }
                    if (hdr.pos_report.isValid() && hdr.pos_report.isValid() && hdr.pos_report.isValid()) {
                        if ((bit<32>)((bit<16>)hdr.pos_report.xway * 16w600 + (bit<16>)(hdr.pos_report.seg + 8w4 << 1) * 16w3 + (bit<16>)hdr.pos_report.dir * 16w3 + 16w2) >= 32w1200) {
                            bug();
                        }
                        stopped_cnt_reg_0.read(meta._stopped_ahead_seg4l222, (bit<32>)((bit<16>)hdr.pos_report.xway * 16w600 + (bit<16>)(hdr.pos_report.seg + 8w4 << 1) * 16w3 + (bit<16>)hdr.pos_report.dir * 16w3 + 16w2));
                    }
                    else {
                        bug();
                    }
                    if (hdr.pos_report.isValid() && hdr.pos_report.isValid() && hdr.pos_report.isValid()) {
                        if ((bit<32>)((bit<16>)hdr.pos_report.xway * 16w600 + (bit<16>)(hdr.pos_report.seg + 8w4 << 1) * 16w3 + (bit<16>)hdr.pos_report.dir * 16w3 + 16w3) >= 32w1200) {
                            bug();
                        }
                        stopped_cnt_reg_0.read(meta._stopped_ahead_seg4l323, (bit<32>)((bit<16>)hdr.pos_report.xway * 16w600 + (bit<16>)(hdr.pos_report.seg + 8w4 << 1) * 16w3 + (bit<16>)hdr.pos_report.dir * 16w3 + 16w3));
                    }
                    else {
                        bug();
                    }
                    meta._stopped_ahead_seg0_ord24 = meta._stopped_ahead_seg0l19 | meta._stopped_ahead_seg0l210 | meta._stopped_ahead_seg0l311;
                    meta._stopped_ahead_seg1_ord25 = meta._stopped_ahead_seg1l112 | meta._stopped_ahead_seg1l213 | meta._stopped_ahead_seg1l314;
                    meta._stopped_ahead_seg2_ord26 = meta._stopped_ahead_seg2l115 | meta._stopped_ahead_seg2l216 | meta._stopped_ahead_seg2l317;
                    meta._stopped_ahead_seg3_ord27 = meta._stopped_ahead_seg3l118 | meta._stopped_ahead_seg3l219 | meta._stopped_ahead_seg3l320;
                    meta._stopped_ahead_seg4_ord28 = meta._stopped_ahead_seg4l121 | meta._stopped_ahead_seg4l222 | meta._stopped_ahead_seg4l323;
                }
                else {
                    ;
                }
                end_load_stopped_ahead_0();
                tmp_42 = query_check_accidents_0(meta._stopped_ahead_seg0_ord24, meta._stopped_ahead_seg1_ord25, meta._stopped_ahead_seg2_ord26, meta._stopped_ahead_seg3_ord27, meta._stopped_ahead_seg4_ord28);
                check_accidents = tmp_42;
                if (check_accidents.hit) {
                    key_match(meta._stopped_ahead_seg0_ord24 <= check_accidents.key_check_accidents_0_stopped_ahead_seg0_ord__max && meta._stopped_ahead_seg0_ord24 >= check_accidents.key_check_accidents_0_stopped_ahead_seg0_ord__min && (meta._stopped_ahead_seg1_ord25 <= check_accidents.key_check_accidents_0_stopped_ahead_seg1_ord__max && meta._stopped_ahead_seg1_ord25 >= check_accidents.key_check_accidents_0_stopped_ahead_seg1_ord__min) && (meta._stopped_ahead_seg2_ord26 <= check_accidents.key_check_accidents_0_stopped_ahead_seg2_ord__max && meta._stopped_ahead_seg2_ord26 >= check_accidents.key_check_accidents_0_stopped_ahead_seg2_ord__min) && (meta._stopped_ahead_seg3_ord27 <= check_accidents.key_check_accidents_0_stopped_ahead_seg3_ord__max && meta._stopped_ahead_seg3_ord27 >= check_accidents.key_check_accidents_0_stopped_ahead_seg3_ord__min) && (meta._stopped_ahead_seg4_ord28 <= check_accidents.key_check_accidents_0_stopped_ahead_seg4_ord__max && meta._stopped_ahead_seg4_ord28 >= check_accidents.key_check_accidents_0_stopped_ahead_seg4_ord__min));
                }
                if (check_accidents.action_run == flow_def_check_accidents_0__action_type_t.NoAction_27) {
                    ;
                }
                else {
                    if (check_accidents.action_run == flow_def_check_accidents_0__action_type_t.set_accident_meta) {
                        angelic_assert(true);
                        if (hdr.pos_report.isValid()) {
                            meta._accident_meta_accident_seg3 = hdr.pos_report.seg + check_accidents.set_accident_meta__ofst;
                        }
                        else {
                            bug();
                        }
                        meta._accident_meta_has_accident_ahead4 = 1w1;
                    }
                    else {
                        ;
                    }
                }
                end_check_accidents_0();
                tmp_43 = query_check_toll_0(meta._v_state_new_seg40, meta._seg_meta_ewma_spd8, meta._seg_meta_vol6, meta._accident_meta_has_accident_ahead4);
                check_toll = tmp_43;
                if (check_toll.hit) {
                    key_match(meta._v_state_new_seg40 == check_toll.key_check_toll_0_v_state_new_seg && (meta._seg_meta_ewma_spd8 <= check_toll.key_check_toll_0_seg_meta_ewma_spd__max && meta._seg_meta_ewma_spd8 >= check_toll.key_check_toll_0_seg_meta_ewma_spd__min) && (meta._seg_meta_vol6 <= check_toll.key_check_toll_0_seg_meta_vol__max && meta._seg_meta_vol6 >= check_toll.key_check_toll_0_seg_meta_vol__min) && meta._accident_meta_has_accident_ahead4 == check_toll.key_check_toll_0_accident_meta_has_accident_ahead);
                }
                if (check_toll.action_run == flow_def_check_toll_0__action_type_t.NoAction_28) {
                    ;
                }
                else {
                    if (check_toll.action_run == flow_def_check_toll_0__action_type_t.issue_toll) {
                        angelic_assert(true);
                        meta._toll_meta_has_toll37 = 1w1;
                        meta._toll_meta_toll36 = check_toll.issue_toll__base_toll * ((bit<16>)meta._seg_meta_vol6 + 16w65486) * ((bit<16>)meta._seg_meta_vol6 + 16w65486);
                        if (hdr.pos_report.isValid()) {
                            if (hdr.pos_report.vid >= 32w512) {
                                bug();
                            }
                            v_accnt_bal_reg_0.read(meta._toll_meta_bal38, hdr.pos_report.vid);
                        }
                        else {
                            bug();
                        }
                        meta._toll_meta_bal38 = meta._toll_meta_bal38 + (bit<32>)(check_toll.issue_toll__base_toll * ((bit<16>)meta._seg_meta_vol6 + 16w65486) * ((bit<16>)meta._seg_meta_vol6 + 16w65486));
                        if (hdr.pos_report.isValid()) {
                            if (hdr.pos_report.vid >= 32w512) {
                                bug();
                            }
                            v_accnt_bal_reg_0.write(hdr.pos_report.vid, meta._toll_meta_bal38);
                        }
                        else {
                            bug();
                        }
                    }
                    else {
                        ;
                    }
                }
                end_check_toll_0();
            }
            else {
                if (hdr.accnt_bal_req.isValid()) {
                    tmp_44 = query_load_accnt_bal_0();
                    load_accnt_bal = tmp_44;
                    if (load_accnt_bal.action_run == flow_def_load_accnt_bal_0__action_type_t.do_load_accnt_bal) {
                        angelic_assert(true);
                        if (hdr.accnt_bal_req.isValid()) {
                            if (hdr.accnt_bal_req.vid >= 32w512) {
                                bug();
                            }
                            v_accnt_bal_reg_0.read(meta._toll_meta_bal38, hdr.accnt_bal_req.vid);
                        }
                        else {
                            bug();
                        }
                    }
                    else {
                        ;
                    }
                    end_load_accnt_bal_0();
                }
            }
            tmp_45 = query_ipv4_lpm_0(hdr.ipv4.dstAddr);
            ipv4_lpm = tmp_45;
            if (ipv4_lpm.hit) {
                key_match(hdr.ipv4.dstAddr & (32w1 << ipv4_lpm.key_ipv4_lpm_0_ipv4_dstAddr__prefix) + 32w4294967295 == ipv4_lpm.key_ipv4_lpm_0_ipv4_dstAddr__val & (32w1 << ipv4_lpm.key_ipv4_lpm_0_ipv4_dstAddr__prefix) + 32w4294967295);
                if (!(hdr.ipv4.isValid() || (32w1 << ipv4_lpm.key_ipv4_lpm_0_ipv4_dstAddr__prefix) + 32w4294967295 == 32w0)) {
                    bug();
                }
            }
            if (ipv4_lpm.action_run == flow_def_ipv4_lpm_0__action_type_t.NoAction_32) {
                ;
            }
            else {
                if (ipv4_lpm.action_run == flow_def_ipv4_lpm_0__action_type_t._drop_4) {
                    angelic_assert(true);
                    standard_metadata.egress_spec = 9w511;
                    __track_egress_spec_0 = true;
                }
                else {
                    if (ipv4_lpm.action_run == flow_def_ipv4_lpm_0__action_type_t.set_nhop) {
                        angelic_assert(true);
                        if (hdr.ipv4.isValid()) {
                            hdr.ipv4.dstAddr = ipv4_lpm.set_nhop__nhop_ipv4;
                        }
                        else {
                            bug();
                        }
                        standard_metadata.egress_spec = ipv4_lpm.set_nhop__port;
                        __track_egress_spec_0 = true;
                    }
                    else {
                        ;
                    }
                }
            }
            end_ipv4_lpm_0();
            tmp_46 = query_forward_0(hdr.ipv4.dstAddr);
            forward = tmp_46;
            if (forward.hit) {
                key_match(hdr.ipv4.dstAddr == forward.key_forward_0_ipv4_dstAddr);
                if (!hdr.ipv4.isValid()) {
                    bug();
                }
            }
            if (forward.action_run == flow_def_forward_0__action_type_t.NoAction_30) {
                ;
            }
            else {
                if (forward.action_run == flow_def_forward_0__action_type_t._drop_2) {
                    angelic_assert(true);
                    standard_metadata.egress_spec = 9w511;
                    __track_egress_spec_0 = true;
                }
                else {
                    if (forward.action_run == flow_def_forward_0__action_type_t.set_dmac) {
                        angelic_assert(true);
                        if (hdr.ethernet.isValid()) {
                            hdr.ethernet.dstAddr = forward.set_dmac__dmac;
                        }
                        else {
                            bug();
                        }
                    }
                    else {
                        ;
                    }
                }
            }
            end_forward_0();
        }
        if (!__track_egress_spec_0) {
            bug();
        }
    }
}

control DeparserImpl(mutable_packet packet, in headers hdr) {
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
    else {
        if (discriminator == 16w3) {
            to._seg_meta_ewma_spd8 = from._seg_meta_ewma_spd8;
            to._seg_meta_prev_vol7 = from._seg_meta_prev_vol7;
            to._seg_meta_vol6 = from._seg_meta_vol6;
            to._toll_egress_meta_recirculate35 = from._toll_egress_meta_recirculate35;
            to._toll_meta_bal38 = from._toll_meta_bal38;
            to._toll_meta_has_toll37 = from._toll_meta_has_toll37;
            to._toll_meta_toll36 = from._toll_meta_toll36;
        }
        else {
            if (discriminator == 16w2) {
                to._accnt_bal_egress_meta_recirculate5 = from._accnt_bal_egress_meta_recirculate5;
                to._toll_meta_bal38 = from._toll_meta_bal38;
                to._toll_meta_has_toll37 = from._toll_meta_has_toll37;
                to._toll_meta_toll36 = from._toll_meta_toll36;
            }
            else {
                if (discriminator == 16w1) {
                    to._accident_egress_meta_recirculate0 = from._accident_egress_meta_recirculate0;
                    to._accident_meta_accident_seg3 = from._accident_meta_accident_seg3;
                    to._accident_meta_cur_stp_cnt1 = from._accident_meta_cur_stp_cnt1;
                    to._accident_meta_has_accident_ahead4 = from._accident_meta_has_accident_ahead4;
                    to._accident_meta_prev_stp_cnt2 = from._accident_meta_prev_stp_cnt2;
                }
                else {
                    ;
                }
            }
        }
    }
}
typedef bit<9> PortId_t;
typedef bit<48> Timestamp_t;
typedef bit<16> CloneSessionId_t;
typedef bit<16> MulticastGroup_t;
typedef bit<16> EgressInstance_t;
typedef bit<3> ClassOfService_t;
typedef bit<32> PacketLength_t;
typedef bit<32> InstanceType_t;
const InstanceType_t PKT_INSTANCE_TYPE_NORMAL_0 = 32w0;
const InstanceType_t PKT_INSTANCE_TYPE_INGRESS_CLONE_0 = 32w1;
const InstanceType_t PKT_INSTANCE_TYPE_EGRESS_CLONE_0 = 32w2;
const InstanceType_t PKT_INSTANCE_TYPE_RESUBMIT_0 = 32w3;
const InstanceType_t PKT_INSTANCE_TYPE_REPLICATION_0 = 32w4;
const InstanceType_t PKT_INSTANCE_TYPE_RECIRC_0 = 32w5;
extern bool platform_port_valid(in PortId_t p);
extern Timestamp_t now();
extern bool is_cpu_port(in PortId_t p);
@controlled extern bool constrain(@readonly mutable_packet pin);
@impl("parse_and_run_") @noreturn extern void parse_and_run(mutable_packet pin, inout metadata metas_, inout standard_metadata_t standard_meta);
@impl("PSAImpl_egress_start_") @noreturn extern void PSAImpl_egress_start(mutable_packet p, inout headers hdrs_, inout metadata metas_, inout standard_metadata_t standard_meta);
@impl("PSAImpl_ingress_start_") @noreturn extern void PSAImpl_ingress_start(mutable_packet p, inout headers hdrs_, inout metadata metas_, inout standard_metadata_t standard_meta);
extern void zero_out<T>(inout T x);
struct clone_session_t {
    bool             exists;
    PortId_t         port;
    EgressInstance_t instance;
}

struct clone_session_properties_t {
    bool             exists;
    ClassOfService_t class_of_service;
    bool             trunc;
    PacketLength_t   plen;
}

@controlled extern clone_session_t qquery_first_clone_pre(in CloneSessionId_t cs);
@controlled extern clone_session_t qquery_all_clone_pre(in CloneSessionId_t cs);
@controlled extern clone_session_t qquery_first_mcast(in MulticastGroup_t cs);
@controlled extern clone_session_properties_t qquery_clone_session_properties(in CloneSessionId_t cs);
void PSAImpl_egress_start_(mutable_packet p, inout headers hdrs_, inout metadata metas_, inout standard_metadata_t standard_meta) {
    headers clone_hdrs_0;
    metadata clone_metas_0;
    standard_metadata_t clone_sm_0;
    CloneSessionId_t clone_session_0;
    CloneSessionId_t clone_field_list_0;
    clone_session_t cs_0;
    bit<32> recirculate_flag_0;
    egress() eg;
    ;
    DeparserImpl() dep;
    ;
    clone_sm_0 = standard_meta;
    clone_hdrs_0 = hdrs_;
    clone_metas_0 = metas_;
    eg.apply(hdrs_, metas_, standard_meta);
    clone_session_0 = standard_meta.clone_spec[15:0];
    clone_field_list_0 = standard_meta.clone_spec[31:16];
    if (clone_session_0 != 16w0) {
        cs_0 = qquery_first_clone_pre(clone_session_0);
        copy_field_list(metas_, clone_metas_0, standard_meta, clone_sm_0, (bit<16>)clone_field_list_0);
        clone_sm_0.instance_type = PKT_INSTANCE_TYPE_EGRESS_CLONE_0;
        clone_sm_0.egress_port = cs_0.port;
        clone_sm_0.resubmit_flag = (bit<32>)32w0;
        clone_sm_0.clone_spec = (bit<32>)32w0;
        if (havoc<bool>()) {
            PSAImpl_egress_start(p, clone_hdrs_0, clone_metas_0, clone_sm_0);
        }
    }
    if (standard_meta.egress_spec == 9w511) {
        do_drop();
    }
    dep.apply(p, hdrs_);
    recirculate_flag_0 = standard_meta.recirculate_flag;
    if (recirculate_flag_0 != 32w0) {
        {
            clone_metas_0._accident_egress_meta_recirculate0 = 1w0;
            clone_metas_0._accident_meta_cur_stp_cnt1 = 8w0;
            clone_metas_0._accident_meta_prev_stp_cnt2 = 8w0;
            clone_metas_0._accident_meta_accident_seg3 = 8w0;
            clone_metas_0._accident_meta_has_accident_ahead4 = 1w0;
            clone_metas_0._accnt_bal_egress_meta_recirculate5 = 1w0;
            clone_metas_0._seg_meta_vol6 = 8w0;
            clone_metas_0._seg_meta_prev_vol7 = 8w0;
            clone_metas_0._seg_meta_ewma_spd8 = 16w0;
            clone_metas_0._stopped_ahead_seg0l19 = 8w0;
            clone_metas_0._stopped_ahead_seg0l210 = 8w0;
            clone_metas_0._stopped_ahead_seg0l311 = 8w0;
            clone_metas_0._stopped_ahead_seg1l112 = 8w0;
            clone_metas_0._stopped_ahead_seg1l213 = 8w0;
            clone_metas_0._stopped_ahead_seg1l314 = 8w0;
            clone_metas_0._stopped_ahead_seg2l115 = 8w0;
            clone_metas_0._stopped_ahead_seg2l216 = 8w0;
            clone_metas_0._stopped_ahead_seg2l317 = 8w0;
            clone_metas_0._stopped_ahead_seg3l118 = 8w0;
            clone_metas_0._stopped_ahead_seg3l219 = 8w0;
            clone_metas_0._stopped_ahead_seg3l320 = 8w0;
            clone_metas_0._stopped_ahead_seg4l121 = 8w0;
            clone_metas_0._stopped_ahead_seg4l222 = 8w0;
            clone_metas_0._stopped_ahead_seg4l323 = 8w0;
            clone_metas_0._stopped_ahead_seg0_ord24 = 8w0;
            clone_metas_0._stopped_ahead_seg1_ord25 = 8w0;
            clone_metas_0._stopped_ahead_seg2_ord26 = 8w0;
            clone_metas_0._stopped_ahead_seg3_ord27 = 8w0;
            clone_metas_0._stopped_ahead_seg4_ord28 = 8w0;
            clone_metas_0._te_md_recirculated29 = 1w0;
            clone_metas_0._te_md_dir30 = 1w0;
            clone_metas_0._te_md_seg_cur31 = 8w0;
            clone_metas_0._te_md_seg_end32 = 8w0;
            clone_metas_0._te_md_toll_sum33 = 16w0;
            clone_metas_0._te_md_time_sum34 = 16w0;
            clone_metas_0._toll_egress_meta_recirculate35 = 1w0;
            clone_metas_0._toll_meta_toll36 = 16w0;
            clone_metas_0._toll_meta_has_toll37 = 1w0;
            clone_metas_0._toll_meta_bal38 = 32w0;
            clone_metas_0._v_state_new39 = 1w0;
            clone_metas_0._v_state_new_seg40 = 1w0;
            clone_metas_0._v_state_prev_spd41 = 8w0;
            clone_metas_0._v_state_prev_xway42 = 8w0;
            clone_metas_0._v_state_prev_lane43 = 3w0;
            clone_metas_0._v_state_prev_seg44 = 8w0;
            clone_metas_0._v_state_prev_dir45 = 1w0;
            clone_metas_0._v_state_prev_nomove_cnt46 = 3w0;
            clone_metas_0._v_state_nomove_cnt47 = 3w0;
        }
        copy_field_list(metas_, clone_metas_0, standard_meta, clone_sm_0, (bit<16>)recirculate_flag_0);
        clone_sm_0.resubmit_flag = (bit<32>)32w0;
        clone_sm_0.clone_spec = (bit<32>)32w0;
        clone_sm_0.recirculate_flag = (bit<32>)32w0;
        clone_sm_0.egress_spec = (bit<9>)9w0;
        clone_sm_0.egress_port = (bit<9>)9w0;
        clone_sm_0.instance_type = PKT_INSTANCE_TYPE_RECIRC_0;
        copy_field_list(metas_, clone_metas_0, standard_meta, clone_sm_0, (bit<16>)recirculate_flag_0);
        parse_and_run(p, clone_metas_0, clone_sm_0);
    }
    do_send(standard_meta.egress_port, p);
}
void PSAImpl_ingress_start_(mutable_packet p, inout headers hdrs_, inout metadata metas_, inout standard_metadata_t standard_meta) {
    headers clone_hdrs_1;
    metadata clone_metas_1;
    standard_metadata_t clone_sm_1;
    CloneSessionId_t clone_session_1;
    CloneSessionId_t clone_field_list_1;
    MulticastGroup_t mgid_0;
    bit<32> resubmit_flag_0;
    clone_session_t cs_1;
    clone_session_t ms_0;
    ingress() ig;
    ;
    clone_sm_1 = standard_meta;
    clone_hdrs_1 = hdrs_;
    clone_metas_1 = metas_;
    ig.apply(hdrs_, metas_, standard_meta);
    clone_session_1 = standard_meta.clone_spec[15:0];
    clone_field_list_1 = standard_meta.clone_spec[31:16];
    mgid_0 = standard_meta.mcast_grp;
    resubmit_flag_0 = standard_meta.resubmit_flag;
    if (clone_session_1 != 16w0) {
        cs_1 = qquery_first_clone_pre(clone_session_1);
        copy_field_list(metas_, clone_metas_1, standard_meta, clone_sm_1, (bit<16>)clone_field_list_1);
        clone_sm_1.egress_port = cs_1.port;
        clone_sm_1.resubmit_flag = (bit<32>)32w0;
        clone_sm_1.clone_spec = (bit<32>)32w0;
        clone_sm_1.recirculate_flag = (bit<32>)32w0;
        clone_sm_1.egress_spec = (bit<9>)9w0;
        clone_sm_1.egress_port = (bit<9>)9w0;
        clone_sm_1.instance_type = PKT_INSTANCE_TYPE_INGRESS_CLONE_0;
        if (havoc<bool>()) {
            PSAImpl_egress_start(p, clone_hdrs_1, clone_metas_1, clone_sm_1);
        }
        standard_meta.resubmit_flag = (bit<32>)32w0;
        standard_meta.clone_spec = (bit<32>)32w0;
        standard_meta.recirculate_flag = (bit<32>)32w0;
    }
    if (resubmit_flag_0 != 32w0) {
        copy_field_list(metas_, clone_metas_1, standard_meta, clone_sm_1, (bit<16>)resubmit_flag_0);
        clone_sm_1 = standard_meta;
        clone_sm_1.resubmit_flag = (bit<32>)32w0;
        clone_sm_1.clone_spec = (bit<32>)32w0;
        clone_sm_1.recirculate_flag = (bit<32>)32w0;
        clone_sm_1.egress_spec = (bit<9>)9w0;
        clone_sm_1.egress_port = (bit<9>)9w0;
        clone_sm_1.instance_type = PKT_INSTANCE_TYPE_RESUBMIT_0;
        PSAImpl_ingress_start(p, clone_hdrs_1, clone_metas_1, clone_sm_1);
    }
    if (mgid_0 != 16w0) {
        standard_meta.instance_type = PKT_INSTANCE_TYPE_REPLICATION_0;
        ms_0 = qquery_first_mcast(mgid_0);
        standard_meta.egress_port = ms_0.port;
        standard_meta.egress_rid = ms_0.instance;
        PSAImpl_egress_start(p, hdrs_, metas_, standard_meta);
    }
    if (standard_meta.egress_spec == 9w511) {
        do_drop();
    }
    standard_meta.egress_port = standard_meta.egress_spec;
    standard_meta.instance_type = PKT_INSTANCE_TYPE_NORMAL_0;
    PSAImpl_egress_start(p, hdrs_, metas_, standard_meta);
}
void parse_and_run_(mutable_packet pin, inout metadata metas_, inout standard_metadata_t standard_meta) {
    error last_0;
    headers hdrs;
    standard_meta.ingress_global_timestamp = now();
    {
        hdrs.accident_alert.setInvalid();
        hdrs.accnt_bal.setInvalid();
        hdrs.accnt_bal_req.setInvalid();
        hdrs.ethernet.setInvalid();
        hdrs.expenditure_report.setInvalid();
        hdrs.expenditure_req.setInvalid();
        hdrs.ipv4.setInvalid();
        hdrs.lr_msg_type.setInvalid();
        hdrs.pos_report.setInvalid();
        hdrs.toll_notification.setInvalid();
        hdrs.travel_estimate.setInvalid();
        hdrs.travel_estimate_req.setInvalid();
        hdrs.udp.setInvalid();
    }
    ParserImpl() p;
    ;
    last_0 = error.NoError;
    p.apply(pin, hdrs, metas_, standard_meta, last_0);
    standard_meta.parser_error = last_0;
    PSAImpl_ingress_start(pin, hdrs, metas_, standard_meta);
}
void run() {
    PortId_t p_0;
    standard_metadata_t standard_meta_0;
    error last_1;
    metadata metas;
    mutable_packet(4096) pin;
    readPacket(pin);
    p_0 = havoc<PortId_t>();
    if (!platform_port_valid(p_0)) {
        do_drop();
    }
    if (is_cpu_port(p_0)) {
        if (!constrain(pin)) {
            do_drop();
        }
    }
    else {
        angelic_assert(true);
    }
    {
        standard_meta_0.ingress_port = 9w0;
        standard_meta_0.egress_spec = 9w0;
        standard_meta_0.egress_port = 9w0;
        standard_meta_0.clone_spec = 32w0;
        standard_meta_0.instance_type = 32w0;
        standard_meta_0.drop = 1w0;
        standard_meta_0.recirculate_port = 16w0;
        standard_meta_0.packet_length = 32w0;
        standard_meta_0.enq_timestamp = 32w0;
        standard_meta_0.enq_qdepth = 19w0;
        standard_meta_0.deq_timedelta = 32w0;
        standard_meta_0.deq_qdepth = 19w0;
        standard_meta_0.ingress_global_timestamp = 48w0;
        standard_meta_0.egress_global_timestamp = 48w0;
        standard_meta_0.lf_field_list = 32w0;
        standard_meta_0.mcast_grp = 16w0;
        standard_meta_0.resubmit_flag = 32w0;
        standard_meta_0.egress_rid = 16w0;
        standard_meta_0.recirculate_flag = 32w0;
        standard_meta_0.checksum_error = 1w0;
        standard_meta_0.priority = 3w0;
        standard_meta_0.deflection_flag = 1w0;
        standard_meta_0.deflect_on_drop = 1w0;
        standard_meta_0.enq_congest_stat = 2w0;
        standard_meta_0.deq_congest_stat = 2w0;
        standard_meta_0.mcast_hash = 13w0;
        standard_meta_0.ingress_cos = 3w0;
        standard_meta_0.packet_color = 2w0;
        standard_meta_0.qid = 5w0;
    }
    standard_meta_0.ingress_port = p_0;
    standard_meta_0.ingress_global_timestamp = now();
    {
        metas._accident_egress_meta_recirculate0 = 1w0;
        metas._accident_meta_cur_stp_cnt1 = 8w0;
        metas._accident_meta_prev_stp_cnt2 = 8w0;
        metas._accident_meta_accident_seg3 = 8w0;
        metas._accident_meta_has_accident_ahead4 = 1w0;
        metas._accnt_bal_egress_meta_recirculate5 = 1w0;
        metas._seg_meta_vol6 = 8w0;
        metas._seg_meta_prev_vol7 = 8w0;
        metas._seg_meta_ewma_spd8 = 16w0;
        metas._stopped_ahead_seg0l19 = 8w0;
        metas._stopped_ahead_seg0l210 = 8w0;
        metas._stopped_ahead_seg0l311 = 8w0;
        metas._stopped_ahead_seg1l112 = 8w0;
        metas._stopped_ahead_seg1l213 = 8w0;
        metas._stopped_ahead_seg1l314 = 8w0;
        metas._stopped_ahead_seg2l115 = 8w0;
        metas._stopped_ahead_seg2l216 = 8w0;
        metas._stopped_ahead_seg2l317 = 8w0;
        metas._stopped_ahead_seg3l118 = 8w0;
        metas._stopped_ahead_seg3l219 = 8w0;
        metas._stopped_ahead_seg3l320 = 8w0;
        metas._stopped_ahead_seg4l121 = 8w0;
        metas._stopped_ahead_seg4l222 = 8w0;
        metas._stopped_ahead_seg4l323 = 8w0;
        metas._stopped_ahead_seg0_ord24 = 8w0;
        metas._stopped_ahead_seg1_ord25 = 8w0;
        metas._stopped_ahead_seg2_ord26 = 8w0;
        metas._stopped_ahead_seg3_ord27 = 8w0;
        metas._stopped_ahead_seg4_ord28 = 8w0;
        metas._te_md_recirculated29 = 1w0;
        metas._te_md_dir30 = 1w0;
        metas._te_md_seg_cur31 = 8w0;
        metas._te_md_seg_end32 = 8w0;
        metas._te_md_toll_sum33 = 16w0;
        metas._te_md_time_sum34 = 16w0;
        metas._toll_egress_meta_recirculate35 = 1w0;
        metas._toll_meta_toll36 = 16w0;
        metas._toll_meta_has_toll37 = 1w0;
        metas._toll_meta_bal38 = 32w0;
        metas._v_state_new39 = 1w0;
        metas._v_state_new_seg40 = 1w0;
        metas._v_state_prev_spd41 = 8w0;
        metas._v_state_prev_xway42 = 8w0;
        metas._v_state_prev_lane43 = 3w0;
        metas._v_state_prev_seg44 = 8w0;
        metas._v_state_prev_dir45 = 1w0;
        metas._v_state_prev_nomove_cnt46 = 3w0;
        metas._v_state_nomove_cnt47 = 3w0;
    }
    standard_meta_0.instance_type = PKT_INSTANCE_TYPE_NORMAL_0;
    parse_and_run(pin, metas, standard_meta_0);
}
