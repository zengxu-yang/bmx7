/*
 * Copyright (c) 2015  Axel Neumann
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of version 2 of the GNU General Public
 * License as published by the Free Software Foundation.
 *
 * This program is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
 * General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA
 * 02110-1301, USA
 */



#define _GNU_SOURCE
#include <stdio.h>
#include <stdarg.h>
#include <syslog.h>
#include <stdlib.h>
#include <errno.h>
#include <string.h>
#include <ctype.h>
#include <sys/un.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <unistd.h>
#include <fcntl.h>
#include <paths.h>
#include <netinet/in.h>
#include <sys/ioctl.h>
#include <json-c/json.h>

#include "list.h"
#include "control.h"
#include "bmx.h"
#include "crypt.h"
#include "avl.h"
#include "node.h"
#include "key.h"
#include "sec.h"
#include "metrics.h"
#include "ogm.h"
#include "msg.h"
#include "desc.h"
#include "content.h"
#include "ip.h"
#include "plugin.h"
#include "schedule.h"
#include "hna.h"
#include "tools.h"
#include "iptools.h"
#include "allocate.h"
#include "prof.h"
#include "accountable.h"


#define CODE_CATEGORY_NAME "accountable"

static int32_t accountableRouteDropping = DEF_ACCOUNTABLE_ROUTE_DROPPING;
static int32_t accountablePrimaryIps = DEF_ACCOUNTABLE_PRIMARY_IPS;
static int32_t accountableDescDropping = DEF_ACCOUNTABLE_DESC_DROPPING;
static int32_t accountableDescSqns = DEF_ACCOUNTABLE_DESC_SQNS;
static int32_t accountableDhashDropping = DEF_ACCOUNTABLE_DHASH_DROPPING;
static int32_t accountableOgmDropping = DEF_ACCOUNTABLE_OGM_DROPPING;
static int32_t accountableOgmMetrics = DEF_ACCOUNTABLE_OGM_METRICS;
static int32_t accountableOgmHash = DEF_ACCOUNTABLE_OGM_HASH;

static struct DirWatch *accountableDirWatch = NULL;
static int32_t accountable_tun_fd = 0;
static int32_t accountable_tun_idx = 0;

static int32_t(*orig_tx_frame_desc_adv) (struct tx_frame_iterator *) = NULL;
static int32_t(*orig_tx_msg_dhash_adv) (struct tx_frame_iterator *) = NULL;
static int32_t(*orig_tx_frame_ogm_dhash_aggreg_advs) (struct tx_frame_iterator *) = NULL;
static int32_t(*orig_tx_dsc_tlv_hna) (struct tx_frame_iterator *) = NULL;
static int32_t(*orig_rx_dsc_tlv_hna) (struct rx_frame_iterator *);

STATIC_FUNC
json_object * fields_dbg_json(uint8_t relevance, uint8_t force_array, uint16_t data_size, uint8_t *data,
	uint16_t min_msg_size, const struct field_format *format)
{
	assertion(-501300, (format && data));

	uint32_t msgs_size = 0;
	uint32_t columns = field_format_get_items(format);

	struct field_iterator it = { .format = format, .data = data, .data_size = data_size, .min_msg_size = min_msg_size };

	json_object *jfields = NULL;
	json_object *jarray = NULL;

	while ((msgs_size = field_iterate(&it)) == SUCCESS) {

		assertion(-501301, IMPLIES(it.field == 0, !jfields));
		/*
		if (it.field == 0 && jfields) {
			jarray = jarray ? jarray : json_object_new_array();
			json_object_array_add(jarray, jfields);
			jfields = NULL;
		}
		 */

		if (format[it.field].field_relevance >= relevance) {

			json_object *jfield_val;

			if (format[it.field].field_type == FIELD_TYPE_UINT && it.field_bits <= 32) {
				jfield_val = json_object_new_int(
					field_get_value(&format[it.field], min_msg_size, data, it.field_bit_pos, it.field_bits));
			} else {
				jfield_val = json_object_new_string(
					field_dbg_value(&format[it.field], min_msg_size, data, it.field_bit_pos, it.field_bits));
			}

			jfields = jfields ? jfields : json_object_new_object();

			json_object_object_add(jfields, format[it.field].field_name, jfield_val);
		}

		if (force_array && it.field == (columns - 1)) {
			jarray = jarray ? jarray : json_object_new_array();
			json_object_array_add(jarray, jfields);
			jfields = NULL;
		}

	}

	assertion(-501302, (data_size ? msgs_size == data_size : msgs_size == min_msg_size));

	return jarray ? jarray : jfields;

	/*
		if (jfields && (force_array || jarray)) {
			jarray = jarray ? jarray : json_object_new_array();
			json_object_array_add(jarray, jfields);
			return jarray;
		}

		return jfields;
	 */
}

STATIC_FUNC
int32_t accountable_tx_frame_description_adv(struct tx_frame_iterator *it)
{

	if (accountableDirWatch && (accountableDescDropping || accountableDescSqns)) {

		DHASH_T *dhash = (DHASH_T*) it->ttn->key.data;
		struct desc_content *dc = avl_find_item(&descContent_tree, dhash);

		if (dc && avl_find(&accountableDirWatch->node_tree, &dc->kn->kHash)) {

			if (accountableDescDropping)
				return TLV_TX_DATA_DONE;

			if (accountableDescSqns) {

				uint8_t *desc = tx_iterator_cache_msg_ptr(it);
				memcpy(desc, dc->desc_frame, dc->desc_frame_len);
				struct dsc_msg_version *verspp;

				get_desc_id(desc, dc->desc_frame_len, NULL, &verspp);
				verspp->descSqn = htonl(ntohl(verspp->descSqn) + 1);

				dbgf_track(DBGT_INFO, "dhash=%s id=%s desc_size=%d INCREMENTED descSqn->%d",
					cryptShaAsString(dhash), cryptShaAsString(&dc->kn->kHash), dc->desc_frame_len, ntohl(verspp->descSqn));

				iid_get_myIID4x_by_node(dc->on);

				return dc->desc_frame_len;
			}
		}
	}

	return(*orig_tx_frame_desc_adv)(it);
}

STATIC_FUNC
int32_t accountable_tx_msg_dhash_adv(struct tx_frame_iterator *it)
{

	if (accountableDirWatch && accountableDhashDropping) {

		IID_T *iid = (IID_T*) it->ttn->key.data;
		MIID_T *in;

		if ((in = iid_get_node_by_myIID4x(*iid)) && avl_find(&accountableDirWatch->node_tree, &in->kn->kHash))
			return TLV_TX_DATA_DONE;
	}

	return(*orig_tx_msg_dhash_adv)(it);
}

STATIC_FUNC
int32_t accountable_tx_frame_ogm_aggreg_advs(struct tx_frame_iterator *it)
{
	struct hdr_ogm_adv *hdr = ((struct hdr_ogm_adv*) tx_iterator_cache_hdr_ptr(it));
	AGGREG_SQN_T *sqn = ((AGGREG_SQN_T *) it->ttn->key.data);
	struct OgmAggreg_node *oan = getOgmAggregNode(*sqn);
	struct avl_node *an = NULL;
	struct orig_node *on;
	struct msg_ogm_adv *msg = (struct msg_ogm_adv*) tx_iterator_cache_msg_ptr(it);

	if (!(accountableDirWatch && (accountableOgmDropping || accountableOgmMetrics || accountableOgmHash)))
		return(*orig_tx_frame_ogm_dhash_aggreg_advs)(it);

	if (tx_iterator_cache_data_space_max(it, 0, 0) < oan->msgsLen)
		return TLV_TX_DATA_FULL;

	hdr->aggregation_sqn = htons(*sqn);

	while ((on = avl_iterate_item(&oan->tree, &an))) {

		assertion(-502661, (on->ogmAggregActiveMsgLen));
		assertion(-502662, (on->dc->ogmSqnMaxSend)); //otherwise on->neighPath might be from last description, but ogm should have been removed during descupdate

		struct KeyWatchNode *tn = avl_find_item(&accountableDirWatch->node_tree, &on->kn->kHash);

		if (tn && accountableOgmDropping)
			continue;

		if (tn && accountableOgmHash)
			cryptRand(&msg->chainOgm, sizeof(msg->chainOgm));
		else
			msg->chainOgm = chainOgmCalc(on->dc, on->dc->ogmSqnMaxSend);

		FMETRIC_U16_T fm16 = umetric_to_fmetric((tn && accountableOgmMetrics) ? UMETRIC_MAX : on->neighPath.um);
		msg->u.f.metric_exp = fm16.val.f.exp_fm16;
		msg->u.f.metric_mantissa = fm16.val.f.mantissa_fm16;
		msg->u.f.hopCount = (tn && accountableOgmMetrics) ? 1 : on->ogmHopCount;
		msg->u.f.transmitterIID4x = iid_get_myIID4x_by_node(on);
		msg->u.f.more = (tn && accountableOgmMetrics) ? 0 : !!on->neighPath.pathMetricsByteSize;

		dbgf_track(DBGT_INFO, "name=%s nodeId=%s iid=%d sqn=%d metric=%ju more=%d hops=%lu (%d) cih=%s chainOgm=%s viaDev=%s",
			on->k.hostname, cryptShaAsShortStr(&on->kn->kHash), msg->u.f.transmitterIID4x, on->dc->ogmSqnMaxSend,
			on->neighPath.um, msg->u.f.more, (on->neighPath.pathMetricsByteSize / sizeof(struct msg_ogm_adv_metric_t0)), on->ogmHopCount,
			memAsHexString(&on->dc->chainOgmConstInputHash, sizeof(msg->chainOgm)),
			memAsHexString(&msg->chainOgm, sizeof(msg->chainOgm)), it->ttn->key.f.p.dev->ifname_label.str);

		msg->u.u32 = htonl(msg->u.u32);

		if (tn && accountableOgmMetrics) {
			msg++;
		} else {
			assertion(-502663, ((on->neighPath.pathMetricsByteSize % sizeof(struct msg_ogm_adv_metric_t0)) == 0));
			uint16_t p;
			for (p = 0; p < (on->neighPath.pathMetricsByteSize / sizeof(struct msg_ogm_adv_metric_t0)); p++) {

				struct msg_ogm_adv_metric_t0 *t0Out = ((struct msg_ogm_adv_metric_t0*) &(msg->mt0[p]));
				struct msg_ogm_adv_metric_t0 *t0In = &(on->neighPath.pathMetrics[p]);
				FMETRIC_U16_T fm = { .val =
					{.f =
						{.exp_fm16 = t0In->u.f.metric_exp, .mantissa_fm16 = t0In->u.f.metric_mantissa } } };

				dbgf_track(DBGT_INFO, "ogmHist=%d more=%d channel=%d origMtc=%s", p + 1, t0In->u.f.more, t0In->channel, umetric_to_human(fmetric_to_umetric(fm)));

				assertion(-502664, (on->neighPath.pathMetrics[p].u.f.more == ((p + 1) < (on->neighPath.pathMetricsByteSize / (uint16_t)sizeof(struct msg_ogm_adv_metric_t0)))));
				t0Out->channel = t0In->channel;
				if (tn && accountableOgmMetrics) {
					struct msg_ogm_adv_metric_t0 t0Accountable = { .u =
						{.u16 = t0In->u.u16 } };
					t0Accountable.u.f.directional = 1;
					t0Accountable.u.f.metric_exp = fm16.val.f.exp_fm16;
					t0Accountable.u.f.metric_mantissa = fm16.val.f.mantissa_fm16;
					t0Out->u.u16 = htons(t0Accountable.u.u16);
				} else {
					t0Out->u.u16 = htons(t0In->u.u16);
				}
			}

			assertion(-502665, (on->ogmAggregActiveMsgLen == ((int) (sizeof(struct msg_ogm_adv) + (p * sizeof(struct msg_ogm_adv_metric_t0))))));
			msg = (struct msg_ogm_adv*) (((uint8_t*) msg) + on->ogmAggregActiveMsgLen);
		}
	}

	dbgf_track(DBGT_INFO, "aggSqn=%d aggSqnMax=%d ogms=%d accountableSize=%d origSize=%d",
		*sqn, ogm_aggreg_sqn_max, oan->tree.items, ((uint32_t) (((uint8_t*) msg) - tx_iterator_cache_msg_ptr(it))), oan->msgsLen);

	return((uint32_t) (((uint8_t*) msg) - tx_iterator_cache_msg_ptr(it)));
}

STATIC_FUNC
void idChanged_Accountable(IDM_T del, struct KeyWatchNode *kwn, struct DirWatch *dw)
{
	dbgf_sys(DBGT_WARN, "del=%d kwn=%d kwnFile=%s kwnGlobalId=%s kwnMisc=%X dw=%d accountableRouteDropping=%d",
		del, !!kwn, kwn ? kwn->fileName : NULL, cryptShaAsShortStr(kwn ? &kwn->global_id : NULL), kwn ? kwn->misc : -1, !!dw, accountableRouteDropping);

	if (!kwn)
		return;

	struct net_key routeKey = { .af = AF_INET6, .mask = 128, .ip = create_crypto_IPv6(&autoconf_prefix_cfg, &kwn->global_id) };

#define KWN_MISC_ROUTE_DROPPING 0x01
#define KWN_MISC_IP_HIJACKING   0x02

	if (!del && !(kwn->misc & KWN_MISC_ROUTE_DROPPING) && accountableRouteDropping) {

		iproute(IP_ROUTE_TUNS, ADD, NO, &routeKey, DEF_ACCOUNTABLE_IP_TABLE, 0, accountable_tun_idx, NULL, NULL, DEF_ACCOUNTABLE_IP_METRIC, NULL);
		kwn->misc |= KWN_MISC_ROUTE_DROPPING;

	} else if (kwn->misc & KWN_MISC_ROUTE_DROPPING) {

		iproute(IP_ROUTE_TUNS, DEL, NO, &routeKey, DEF_ACCOUNTABLE_IP_TABLE, 0, accountable_tun_idx, NULL, NULL, DEF_ACCOUNTABLE_IP_METRIC, NULL);
		kwn->misc &= (~KWN_MISC_ROUTE_DROPPING);
	}


	if (!del && !(kwn->misc & KWN_MISC_IP_HIJACKING) && accountablePrimaryIps) {

		my_description_changed = YES;
		kwn->misc |= KWN_MISC_IP_HIJACKING;

	} else if (kwn->misc & KWN_MISC_IP_HIJACKING) {

		my_description_changed = YES;
		kwn->misc &= (~KWN_MISC_IP_HIJACKING);
	}



	if (del) {
		avl_remove(&dw->node_tree, &kwn->global_id, -300770);
		debugFree(kwn, -300771);
	}
}

STATIC_FUNC
void tun_out_devZero_hook(int fd)
{
	static uint8_t tp[2000];

	while (read(fd, &tp, sizeof(tp)) > 0);
}

STATIC_FUNC
int32_t opt_accountable_route(uint8_t cmd, uint8_t _save, struct opt_type *opt, struct opt_parent *patch, struct ctrl_node *cn)
{

	if (cmd == OPT_APPLY) {

		dbgf_sys(DBGT_INFO, "changing %s=%d", opt->name, accountableRouteDropping);

		struct KeyWatchNode *kwn;
		struct avl_node *an = NULL;
		while (accountableDirWatch && (kwn = avl_iterate_item(&accountableDirWatch->node_tree, &an)))
			(*accountableDirWatch->idChanged)(ADD, kwn, accountableDirWatch);

	}


	return SUCCESS;
}

STATIC_FUNC
int32_t opt_accountable_watch(uint8_t cmd, uint8_t _save, struct opt_type *opt, struct opt_parent *patch, struct ctrl_node *cn)
{

	assertion(-502520, ((strcmp(opt->name, ARG_ATTACKED_NODES_DIR) == 0)));

	if (cmd == OPT_CHECK && patch->diff == ADD && check_dir(patch->val, YES/*create*/, YES/*writable*/, NO) == FAILURE)
		return FAILURE;

	if (cmd == OPT_APPLY) {

		if (patch->diff == DEL)
			cleanup_dir_watch(&accountableDirWatch);

		if (patch->diff == ADD) {
			assertion(-501286, (patch->val));
			return init_dir_watch(&accountableDirWatch, patch->val, idChanged_Accountable);
		}
	}

	return SUCCESS;
}

STATIC_FUNC
int32_t opt_accountable_init(uint8_t cmd, uint8_t _save, struct opt_type *opt, struct opt_parent *patch, struct ctrl_node *cn)
{

	if (cmd == OPT_CHECK || cmd == OPT_APPLY)
		return FAILURE;

	if (cmd == OPT_SET_POST && initializing) {

		accountable_tun_idx = kernel_dev_tun_add(DEF_ACCOUNTABLE_TUN_NAME, &accountable_tun_fd, NO);
		set_fd_hook(accountable_tun_fd, tun_out_devZero_hook, ADD);

		ip_flush_routes(AF_INET6, DEF_ACCOUNTABLE_IP_TABLE);
		ip_flush_rules(AF_INET6, DEF_ACCOUNTABLE_IP_TABLE);

		// must be configured after general IPv6 options:
		iproute(IP_RULE_DEFAULT, ADD, NO, &ZERO_NET6_KEY, DEF_ACCOUNTABLE_IP_TABLE, DEF_ACCOUNTABLE_IP_RULE, 0, 0, 0, 0, NULL);
	}

	return SUCCESS;
}

STATIC_FUNC
int accountable_rx_dsc_tlv_hna(struct rx_frame_iterator *it)
{
	ASSERTION(-500357, (it->f_type == BMX_DSC_TLV_HNA6));
	assertion(-502326, (it->dcOp && it->dcOp->kn));

	if (it->dcOp->kn == myKey)
		return it->f_msgs_len;
	else
		return orig_rx_dsc_tlv_hna(it);
}

STATIC_FUNC
int accountable_tx_dsc_tlv_hna(struct tx_frame_iterator *it)
{
	dbgf_sys(DBGT_INFO, "enabled=%d attacked nodes=%d", accountablePrimaryIps, accountableDirWatch ? (int) accountableDirWatch->node_tree.items : -1);

	if (!accountablePrimaryIps || !accountableDirWatch || !accountableDirWatch->node_tree.items)
		return((*orig_tx_dsc_tlv_hna)(it));

	assertion(-500765, (it->frame_type == BMX_DSC_TLV_HNA6));

	uint8_t *data = tx_iterator_cache_msg_ptr(it);
	uint32_t max_size = tx_iterator_cache_data_space_pref(it, 0, 0);
	uint32_t pos = 0;
	struct avl_node *an = NULL;

	struct KeyWatchNode *kwn;
	for (an = NULL; (kwn = avl_iterate_item(&accountableDirWatch->node_tree, &an));) {
		IPX_T attacked_primary_ip = create_crypto_IPv6(&autoconf_prefix_cfg, &kwn->global_id);
		pos = create_tlv_hna(data, max_size, pos, setNet(NULL, AF_INET6, 128, &attacked_primary_ip), 0);
		dbgf_sys(DBGT_INFO, "Hijacking ip=%s", ip6AsStr(&attacked_primary_ip));
	}
/*
        if (!is_ip_set(&my_primary_ip))
                return TLV_TX_DATA_IGNORED;

        pos = _create_tlv_hna(data, max_size, pos, setNet(NULL, AF_INET6, 128, &my_primary_ip), 0);


	struct tun_in_node *tin;
	for (an = NULL; (tin = avl_iterate_item(&tun_in_tree, &an));) {
		if (tin->upIfIdx && tin->tun6Id >= 0 && is_ip_set(&tin->remoteDummyIp6)) {
			assertion(-501237, (tin->upIfIdx && tin->tun6Id >= 0));
			pos = _create_tlv_hna(data, max_size, pos, setNet(NULL, AF_INET6, 128, &tin->remoteDummyIp6), DESC_MSG_HNA_FLAG_NO_ROUTE);
		}
	}

	struct opt_parent *p = NULL;
	while ((p = list_iterate(&(get_option(NULL, NO, ARG_UHNA)->d.parents_instance_list), p))) {
		struct net_key hna = ZERO_NETCFG_KEY;
		str2netw(p->val, &hna.ip, NULL, &hna.mask, &hna.af, NO);
		assertion(-502325, (is_ip_valid(&hna.ip, hna.af)));
		pos = _create_tlv_hna(data, max_size, pos, &hna, 0);
	}
*/
        return pos;
}

struct accountable_status {
	struct CRYPTSHA_T key;
	struct CRYPTSHA_T id;
};

static const struct field_format accountable_status_format[] = {
	FIELD_FORMAT_INIT(FIELD_TYPE_GLOBAL_ID,	accountable_status, key,	1, FIELD_RELEVANCE_HIGH),
	FIELD_FORMAT_INIT(FIELD_TYPE_GLOBAL_ID,	accountable_status, id,	1, FIELD_RELEVANCE_HIGH),
	FIELD_FORMAT_END
};

static int32_t opt_acct_status_generic(uint8_t cmd, uint8_t _save, struct opt_type *opt, struct opt_parent *patch, struct ctrl_node *cn,
	uint32_t(fields_dbg_func) (struct ctrl_node *cn, uint16_t relevance, uint32_t data_size, uint8_t *data, uint32_t min_msg_size, const struct field_format *format)
	)
{
	if (cmd == OPT_CHECK || cmd == OPT_APPLY) {

		int32_t relevance = get_opt_child_val_int(opt, patch, ARG_RELEVANCE, DEF_RELEVANCE);
		int32_t json = get_opt_child_val_int(opt, patch, ARG_JSON, DEF_JSON);
		struct status_handl *handl;

		if ((handl = get_status_handl(opt->name))) {

			if (cmd == OPT_APPLY) {

				uint32_t data_len;

				prof_start(opt_acct_status_generic, main);

				if ((data_len = ((*(handl->frame_creator))(handl, patch->val)))) {
					if (!json)
					{
						uint16_t i;
						char upper[strlen(handl->status_name) + 1];
						for (i = 0; (i <= strlen(handl->status_name)); i++)
							upper[i] = toupper(handl->status_name[i]);
						dbg_printf(cn, "%s:\n", upper);
						fields_dbg_func(cn, relevance, data_len, handl->data, handl->min_msg_size, handl->format);
					} else {
						json_object *jstat = json_object_new_object();
						json_object *jstat_fields = NULL;

						if ((jstat_fields = fields_dbg_json(relevance, handl->multiline,
										    data_len, handl->data, handl->min_msg_size, handl->format))) {
							
							json_object_object_add(jstat, handl->status_name, jstat_fields);
						}

						if (cn)
							dbg_printf(cn, "%s\n", json_object_to_json_string(jstat));
					
						json_object_put(jstat); 
					} 
				}

				prof_stop();
			}

		} else {

			struct avl_node *it = NULL;
			dbg_printf(cn, "requested %s must be one of: ", ARG_VALUE_FORM);
			while ((handl = avl_iterate_item(&status_tree, &it))) {
				dbg_printf(cn, "%s ", handl->status_name);
			}
			dbg_printf(cn, "\n");
			return FAILURE;
		}
	}
	return SUCCESS;
}

static int32_t opt_acct_status(uint8_t cmd, uint8_t _save, struct opt_type *opt, struct opt_parent *patch, struct ctrl_node *cn)
{
	return opt_acct_status_generic(cmd, _save, opt, patch, cn, fields_dbg_table);
}

static int32_t accountable_status_creator(struct status_handl *handl, void *data)
{
	int32_t status_size = sizeof(struct accountable_status);

	struct orig_node *on;
	struct dsc_msg_dhm_link_key *DhmKey = NULL;
	int DhmLen = 0;

	struct accountable_status *status = (struct accountable_status *)(handl->data = debugRealloc(handl->data, status_size, -505001));
	memset(status, 0, status_size);

	if (strlen(data) != (int) (2 * sizeof(status->id)))
		return 0;

	if (hexStrToMem(data, (uint8_t*) & status->id, sizeof(status->id), YES/*strict*/) != SUCCESS)
		return 0;

	if((on = avl_find_item(&orig_tree, &status->id)) !=  NULL && ! cryptShasEqual(&on->k.nodeId, &myKey->kHash))
	{
		if(on->dhmSecret != NULL)
			status->key = *on->dhmSecret;
		else
		{
			if (my_DhmLinkKey &&
			    (DhmKey = contents_data(on->dc, BMX_DSC_TLV_DHM_LINK_PUBKEY)) &&
			    (DhmLen = ((int) contents_dlen(on->dc, BMX_DSC_TLV_DHM_LINK_PUBKEY) - sizeof(struct dsc_msg_dhm_link_key))) &&
			    (DhmLen == my_DhmLinkKey->rawGXLen) && (DhmKey->type == my_DhmLinkKey->rawGXType)) {
				if(on->dhmSecret = cryptDhmSecretForNeigh(my_DhmLinkKey, DhmKey->gx, DhmLen))
					status->key = *on->dhmSecret;
				
			}
		}
	}
	else
		for (int i = 0; i < CRYPT_SHA_LEN / sizeof(uint32_t); i++)
		{
			status->key.h.u32[i] = 0x55aa;
		}
	
	return status_size;

accountable_status_error:

	return FAILURE;
}

static struct opt_type accountable_options[] = {
//        ord parent long_name          shrt Attributes				*ival		min		max		default		*func,*syntax,*help
	{ODI,0,"accountableInit",              0,  8,0,A_PS0,A_ADM,A_INI,A_ARG,A_ANY,	0,		0,		0,		0,0,            opt_accountable_init,
			NULL,HLP_DUMMY_OPT},
	{ODI,0,ARG_ATTACKED_NODES_DIR,  0,  9,2,A_PS1,A_ADM,A_DYI,A_CFA,A_ANY,	0,		0,		0,		0,DEF_ATTACKED_NODES_DIR, opt_accountable_watch,
			ARG_DIR_FORM,"Directory with global-id hashes of this node's attacked other nodes"},
	{ODI,0,ARG_ACCOUNTABLE_ROUTE_DROPPING, 0,  9,2,A_PS1,A_ADM,A_DYI,A_CFA,A_ANY, &accountableRouteDropping,MIN_ACCOUNTABLE_ROUTE_DROPPING,MAX_ACCOUNTABLE_ROUTE_DROPPING,DEF_ACCOUNTABLE_ROUTE_DROPPING,0,opt_accountable_route,
			ARG_VALUE_FORM, "Do not forward IPv6 packets towards attacked nodes"},
	{ODI,0,ARG_ACCOUNTABLE_PRIMARY_IPS,    0,  9,2,A_PS1,A_ADM,A_DYI,A_CFA,A_ANY, &accountablePrimaryIps,   MIN_ACCOUNTABLE_PRIMARY_IPS,MAX_ACCOUNTABLE_PRIMARY_IPS,DEF_ACCOUNTABLE_PRIMARY_IPS,0,opt_accountable_route,
			ARG_VALUE_FORM, "Do not forward IPv6 packets towards attacked nodes"},
	{ODI,0,ARG_ACCOUNTABLE_DESC_DROPPING,  0,  9,2,A_PS1,A_ADM,A_DYI,A_CFA,A_ANY, &accountableDescDropping, MIN_ACCOUNTABLE_DESC_DROPPING,MAX_ACCOUNTABLE_DESC_DROPPING,DEF_ACCOUNTABLE_DESC_DROPPING,0,NULL,
			ARG_VALUE_FORM, "Do not propagate description updates of attacked nodes"},
	{ODI,0,ARG_ACCOUNTABLE_DESC_SQNS,      0,  9,2,A_PS1,A_ADM,A_DYI,A_CFA,A_ANY, &accountableDescSqns,     MIN_ACCOUNTABLE_DESC_SQNS,MAX_ACCOUNTABLE_DESC_SQNS,DEF_ACCOUNTABLE_DESC_SQNS,0,NULL,
			ARG_VALUE_FORM, "Increment description sqn of attacked nodes"},
	{ODI,0,ARG_ACCOUNTABLE_DHASH_DROPPING, 0,  9,2,A_PS1,A_ADM,A_DYI,A_CFA,A_ANY, &accountableDhashDropping,MIN_ACCOUNTABLE_DHASH_DROPPING,MAX_ACCOUNTABLE_DHASH_DROPPING,DEF_ACCOUNTABLE_DHASH_DROPPING,0,NULL,
			ARG_VALUE_FORM, "Do not propagate description hash (Dhash) updates of attacked nodes"},
	{ODI,0,ARG_ACCOUNTABLE_OGM_DROPPING,   0,  9,2,A_PS1,A_ADM,A_DYI,A_CFA,A_ANY, &accountableOgmDropping,  MIN_ACCOUNTABLE_OGM_DROPPING,MAX_ACCOUNTABLE_OGM_DROPPING,DEF_ACCOUNTABLE_OGM_DROPPING,0,NULL,
			ARG_VALUE_FORM, "Do not propagate routing updates (OGMs) of attacked nodes"},
	{ODI,0,ARG_ACCOUNTABLE_OGM_METRICS,    0,  9,2,A_PS1,A_ADM,A_DYI,A_CFA,A_ANY, &accountableOgmMetrics,   MIN_ACCOUNTABLE_OGM_METRICS,MAX_ACCOUNTABLE_OGM_METRICS,DEF_ACCOUNTABLE_OGM_METRICS,0,NULL,
			ARG_VALUE_FORM, "Modify metrics of routing updates (OGMs) of attacked nodes"},
	{ODI,0,ARG_ACCOUNTABLE_OGM_HASH,       0,  9,0,A_PS1,A_ADM,A_DYI,A_CFA,A_ANY, &accountableOgmHash,      MIN_ACCOUNTABLE_OGM_HASH,MAX_ACCOUNTABLE_OGM_HASH,DEF_ACCOUNTABLE_OGM_HASH,0,NULL,
	 ARG_VALUE_FORM, "Randomize hash-chain value of routing updates (OGMs) of attacked nodes"},
	{ODI,0,ARG_ACCT,	        0,9,2,A_PS1N,A_USR,A_DYN,A_ARG,A_ANY,	0,		0, 		0,		0,0, 		opt_acct_status,
	 0,		"show symmetric keys"},
	{ODI,ARG_ACCT,ARG_RELEVANCE,'r',9,1,A_CS1,A_USR,A_DYN,A_ARG,A_ANY,	0,	       MIN_RELEVANCE,   MAX_RELEVANCE,  DEF_RELEVANCE,0, opt_acct_status,
	 ARG_VALUE_FORM,	HLP_ARG_RELEVANCE},
	{ODI,ARG_ACCT,ARG_JSON,'j',9,1,A_CS1,A_USR,A_DYN,A_ARG,A_ANY,	0,	       MIN_JSON,   MAX_JSON,  DEF_JSON,0, opt_acct_status,
			ARG_VALUE_FORM,	HLP_ARG_JSON}
};

static int32_t accountable_init(void)
{
	register_options_array(accountable_options, sizeof( accountable_options), CODE_CATEGORY_NAME);

	orig_tx_frame_desc_adv = packet_frame_db->handls[FRAME_TYPE_DESC_ADVS].tx_frame_handler;
	packet_frame_db->handls[FRAME_TYPE_DESC_ADVS].tx_frame_handler = accountable_tx_frame_description_adv;

	orig_tx_msg_dhash_adv = packet_frame_db->handls[FRAME_TYPE_IID_ADV].tx_msg_handler;
	packet_frame_db->handls[FRAME_TYPE_IID_ADV].tx_msg_handler = accountable_tx_msg_dhash_adv;

	orig_tx_frame_ogm_dhash_aggreg_advs = packet_frame_db->handls[FRAME_TYPE_OGM_ADV].tx_frame_handler;
	packet_frame_db->handls[FRAME_TYPE_OGM_ADV].tx_frame_handler = accountable_tx_frame_ogm_aggreg_advs;

	orig_tx_dsc_tlv_hna = description_tlv_db->handls[BMX_DSC_TLV_HNA6].tx_frame_handler;
	description_tlv_db->handls[BMX_DSC_TLV_HNA6].tx_frame_handler = accountable_tx_dsc_tlv_hna;

	orig_rx_dsc_tlv_hna = description_tlv_db->handls[BMX_DSC_TLV_HNA6].rx_frame_handler;
	description_tlv_db->handls[BMX_DSC_TLV_HNA6].rx_frame_handler = accountable_rx_dsc_tlv_hna;


	register_status_handl(sizeof(struct accountable_status), 1, accountable_status_format, ARG_ACCT, accountable_status_creator);

	return SUCCESS;
}

static void accountable_cleanup(void)
{
	packet_frame_db->handls[FRAME_TYPE_DESC_ADVS].tx_frame_handler = orig_tx_frame_desc_adv;
	packet_frame_db->handls[FRAME_TYPE_IID_ADV].tx_msg_handler = orig_tx_msg_dhash_adv;
	packet_frame_db->handls[FRAME_TYPE_OGM_ADV].tx_frame_handler = orig_tx_frame_ogm_dhash_aggreg_advs;
	description_tlv_db->handls[BMX_DSC_TLV_HNA6].tx_frame_handler = orig_tx_dsc_tlv_hna;
	description_tlv_db->handls[BMX_DSC_TLV_HNA6].rx_frame_handler = orig_rx_dsc_tlv_hna;

	cleanup_dir_watch(&accountableDirWatch);

	if (accountable_tun_fd) {
		iproute(IP_RULE_DEFAULT, DEL, NO, &ZERO_NET6_KEY, DEF_ACCOUNTABLE_IP_TABLE, DEF_ACCOUNTABLE_IP_RULE, 0, 0, 0, 0, NULL);

		ip_flush_routes(AF_INET6, DEF_ACCOUNTABLE_IP_TABLE);
		ip_flush_rules(AF_INET6, DEF_ACCOUNTABLE_IP_TABLE);

		set_fd_hook(accountable_tun_fd, tun_out_devZero_hook, DEL);
		kernel_dev_tun_del(DEF_ACCOUNTABLE_TUN_NAME, accountable_tun_fd);
		accountable_tun_fd = 0;
	}
}

struct plugin* get_plugin(void)
{

	static struct plugin accountable_plugin;

	memset(&accountable_plugin, 0, sizeof( struct plugin));


	accountable_plugin.plugin_name = CODE_CATEGORY_NAME;
	accountable_plugin.plugin_size = sizeof( struct plugin);
	accountable_plugin.cb_init = accountable_init;
	accountable_plugin.cb_cleanup = accountable_cleanup;

	return &accountable_plugin;
}
