/*
 * Copyright (c) 2010  Axel Neumann
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
#include <arpa/inet.h>
#include <stdio.h>
#include <errno.h>
#include <sys/types.h>
#include <unistd.h>
#include <signal.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <linux/if.h>     /* ifr_if, ifr_tun */
#include <linux/rtnetlink.h>
#include <time.h>


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
#include "link.h"
#include "msg.h"
#include "desc.h"
#include "content.h"
#include "ip.h"
#include "hna.h"
#include "schedule.h"
#include "tools.h"
#include "iptools.h"
#include "plugin.h"
#include "allocate.h"
#include "z.h"

#define CODE_CATEGORY_NAME "node"

IDM_T my_description_changed = YES;

struct key_node *myKey = NULL;


AVL_TREE(link_tree, LinkNode, k);

AVL_TREE(link_dev_tree, LinkDevNode, key);

AVL_TREE(local_tree, struct neigh_node, local_id);

AVL_TREE(descContent_tree, struct desc_content, dHash);


AVL_TREE(orig_tree, struct orig_node, k.nodeId);


void neighRef_destroy(struct NeighRef_node *ref, IDM_T reAssessState)
{
	assertion(-502454, (ref && ref->nn));
	struct key_node *kn = ref->kn;

	if (ref->scheduled_ogm_processing)
		task_remove(process_ogm_metric, (void*)ref);

	iid_free(&ref->nn->neighIID4x_repos, iid_get_neighIID4x_by_node(ref, NO, YES), NO);

	if (kn)
		avl_remove(&kn->neighRefs_tree, &ref->nn, -300717);

	if (reAssessState && kn && kn != ref->nn->on->kn)
		keyNode_delCredits(NULL, kn, NULL);

	if (ref->inaptChainOgm)
		debugFree(ref->inaptChainOgm, -300000);

	debugFree(ref, -300721);
}


STATIC_FUNC
struct NeighRef_node *neighRef_create_(struct neigh_node *neigh, AGGREG_SQN_T aggSqn, IID_T neighIID4x)
{
	assertion(-502455, (neigh));
	assertion(-500000, (!iid_get_node_by_neighIID4x(&neigh->neighIID4x_repos, neighIID4x, NO, NULL)));

	struct NeighRef_node *ref = debugMallocReset(sizeof(struct NeighRef_node), -300000);

	ref->nn = neigh;
	ref->aggSqn = aggSqn;
	iid_set_neighIID4x(&neigh->neighIID4x_repos, neighIID4x, ref);

	return ref;
}

STATIC_FUNC
struct NeighRef_node *neighRef_maintain(struct NeighRef_node *ref)
{
	IID_T iid;

	if ((iid = iid_get_neighIID4x_by_node(ref, NO, NO))) {

		struct key_node *kn = ref->kn;
		struct neigh_node *nn = ref->nn;

		if (!kn) {

			schedule_tx_task(FRAME_TYPE_IID_REQ, &nn->local_id, nn, nn->best_tp_link->k.myDev, SCHEDULE_MIN_MSG_SIZE, &iid, sizeof(iid));

		} else if (kn->bookedState->i.c >= KCTracked && kn->content->f_body && (ref->inaptChainOgm || (!kn->on && !kn->nextDesc))) {

			schedule_tx_task(FRAME_TYPE_DESC_REQ, &nn->local_id, nn, nn->best_tp_link->k.myDev, SCHEDULE_MIN_MSG_SIZE, &iid, sizeof(iid));
		}
		return ref;


	} else {
		neighRef_destroy(ref, YES);
		return NULL;
	}
}



STATIC_FUNC
void neighRefs_maintain(void)
{
	static TIME_T next = 0;
	GLOBAL_ID_T nid = ZERO_CYRYPSHA1;
	struct neigh_node *nn;
	IID_T iid;
	struct NeighRef_node *ref;

	if (!doNowOrLater(&next, refRslvInterval, 0))
		return;

	while ((nn = avl_next_item(&local_tree, &nid))) {
		nid = nn->local_id;

		for (iid = 0; iid < nn->neighIID4x_repos.max_free; iid++) {

			if ((ref = iid_get_node_by_neighIID4x(&nn->neighIID4x_repos, iid, NO, NULL)))
				neighRef_maintain(ref);

		}
	}
}

STATIC_FUNC
void inaptChainOgm_destroy_(struct NeighRef_node *ref)
{
	if (ref->inaptChainOgm) {
		debugFree(ref->inaptChainOgm->chainOgm, -300000);
		debugFree(ref->inaptChainOgm, -300000);
		ref->inaptChainOgm = NULL;
	}
}


STATIC_FUNC
void inaptChainOgm_update_(struct NeighRef_node *ref, struct InaptChainOgm *inaptChainOgm)
{
	if (!ref->inaptChainOgm) {
		ref->inaptChainOgm = debugMalloc(sizeof(struct InaptChainOgm), -300000);
		ref->inaptChainOgm->chainOgm = debugMalloc(sizeof(ChainLink_T), -300000);
	}

	*ref->inaptChainOgm->chainOgm = *inaptChainOgm->chainOgm;
	ref->inaptChainOgm->ogmMtc = inaptChainOgm->ogmMtc;
}

struct NeighRef_node *neighRef_update(struct neigh_node *nn, AGGREG_SQN_T aggSqn, IID_T neighIID4x, CRYPTSHA1_T *kHash, DESC_SQN_T descSqn, struct InaptChainOgm *inChainOgm)
{
	assertion(-502459, (nn));
	assertion(-500000, (neighIID4x));
	assertion(-500000, IMPLIES((kHash || descSqn), (kHash && descSqn)));

	char *goto_error_code = NULL;
	struct NeighRef_node *goto_error_ret = NULL;
	struct NeighRef_node *ref = NULL;
	struct key_node *kn = NULL;
	struct desc_content *dc = NULL;
	OGM_SQN_T ogmSqn = 0;
	struct InaptChainOgm *chainOgm = NULL;

	if (!(ref = iid_get_node_by_neighIID4x(&nn->neighIID4x_repos, neighIID4x, YES, NULL)) && !(ref = neighRef_create_(nn, aggSqn, neighIID4x)))
		goto_error_return( finish, "No neighRef!!!", NULL);

	if (kHash) {

		if (ref->kn && cryptShasEqual(&ref->kn->kHash, kHash)) {

			kn = ref->kn;

		} else {
			if (ref->kn) {
				neighRef_destroy(ref, YES);
				ref = neighRef_create_(nn, aggSqn, neighIID4x);
			}

			struct key_credits kc = {.neighRef = ref};
			if (!(kn = keyNode_updCredits(kHash, NULL, &kc))) {
				neighRef_destroy(ref, YES);
				ref = NULL;
				goto_error_return( finish, "Insufficient credits", NULL);
			}
		}

		ref->descSqn = (descSqn > ref->descSqn) ? descSqn : ref->descSqn;
	} else {
		kn = ref->kn;
	}

	ref->aggSqn = (((AGGREG_SQN_T) (ref->aggSqn - aggSqn)) < AGGREG_SQN_CACHE_RANGE) ? ref->aggSqn : aggSqn;

	if (kn && kn->nextDesc && kn->nextDesc->descSqn == ref->descSqn)
		dc = kn->nextDesc;
	else if (kn && kn->on && kn->on->dc->descSqn == ref->descSqn)
		dc = kn->on->dc;

	if ((chainOgm = inChainOgm ? inChainOgm : ref->inaptChainOgm)) {

		if (dc && ((ogmSqn = chainOgmFind(chainOgm->chainOgm, dc)) != dc->ogmSqnZero)) {

			assertion(-500000, (((OGM_SQN_T) (dc->ogmSqnZero + dc->ogmSqnRange - ogmSqn)) <= dc->ogmSqnRange));

			if (((OGM_SQN_T) (ogmSqn - ref->ogmSqnMaxRcvd)) > dc->ogmSqnRange)
				goto_error_return(finish, "Outdated ogmSqn", NULL);

			dc->referred_by_others_timestamp = bmx_time;

			ref->ogmSqnMaxRcvd = ogmSqn;
			ref->ogmMtcMaxRcvd.val.u16 = (ref->inaptChainOgm && !memcmp(ref->inaptChainOgm->chainOgm, chainOgm->chainOgm, sizeof(ChainLink_T))) ?
				XMAX(ref->inaptChainOgm->ogmMtc.val.u16, chainOgm->ogmMtc.val.u16) :
				chainOgm->ogmMtc.val.u16;

			inaptChainOgm_destroy_(ref);

		} else {

			if (kn && kn->bookedState->i.c >= KCTracked)
				inaptChainOgm_update_(ref, chainOgm);
			else
				inaptChainOgm_destroy_(ref);

			ref = neighRef_maintain(ref);
			goto_error_return(finish, "Unresolved ogmSqn", NULL);
		}
	}

	if (kn && dc && dc->on && dc->descSqn == ref->descSqn &&
		(((OGM_SQN_T) (ref->ogmSqnMaxRcvd - dc->ogmSqnZero)) >= 1) &&
		(((OGM_SQN_T) (ref->ogmSqnMaxRcvd - dc->ogmSqnZero)) <= dc->ogmSqnRange)
		) {
		assertion(-500000, (nn && nn == ref->nn));
		assertion(-500000, (kn && kn == ref->kn));
		assertion(-500000, (dc && dc == ref->kn->on->dc));

		if ((((OGM_SQN_T) (ref->ogmSqnMaxRcvd - ref->ogmProcessedSqn)) < dc->ogmSqnRange) &&
			(ref->ogmMtcMaxRcvd.val.u16 > ref->ogmProcessedMetricMax.val.u16)) {

			if (ref->ogmSqnMaxRcvd != ref->ogmProcessedSqn) {
				ref->ogmProcessedSqn = ref->ogmSqnMaxRcvd;
				ref->ogmProcessedSqnTime = bmx_time;
			}

			ref->ogmProcessedMetricMax = ref->ogmMtcMaxRcvd;

			process_ogm_metric(ref);
		}

		goto_error_return(finish, "SUCCESS", ref);
	}

finish: {
	dbgf_track(DBGT_INFO, 
		"problem=%s neigh=%s aggSqn=%d IID=%d kHash=%s descSqn=%d chainOgm=%s ogmMtc=%d \n"
		"REF: nodeId=%s descSqn=%d hostname=%s ogmSqnMaxRcvd=%d ogmSqnProcessed=%d ogmMtc=%d \n"
		"DC: ogmSqnZero=%d ogmSqnRange=%d  \n"
		"OUT: ogmSqn=%d ",
		goto_error_code, ((nn && nn->on) ? nn->on->k.hostname : NULL), aggSqn, neighIID4x, cryptShaAsShortStr(kHash), descSqn,
		memAsHexString(inChainOgm ? inChainOgm->chainOgm : NULL, sizeof(ChainLink_T)), (inChainOgm ? (int)inChainOgm->ogmMtc.val.u16 : -1),
		cryptShaAsShortStr(ref && ref->kn ? &ref->kn->kHash : NULL),
		(ref ? (int)ref->descSqn : -1 ),
		(ref && ref->kn && ref->kn->on ? ref->kn->on->k.hostname : NULL),
		(ref ? (int)ref->ogmSqnMaxRcvd : -1),
		(ref ? (int)ref->ogmProcessedSqn : -1),
		(ref ? (int)ref->ogmMtcMaxRcvd.val.u16 : -1),
		(dc ? (int)dc->ogmSqnZero : -1), (dc ? (int)dc->ogmSqnRange : -1), (dc ? (int)dc->ogmSqnMaxRcvd : -1),
		ogmSqn);


	return goto_error_ret;
}
}

void neighRefs_update(struct key_node *kn) {

	assertion(-500000, (kn && (kn->nextDesc || kn->on)));

	struct NeighRef_node *nref;
	struct neigh_node *nn;
	IID_T iid;
	for (nn = NULL; (nref = avl_next_item(&kn->neighRefs_tree, &nn));) {
		if ((iid = iid_get_neighIID4x_by_node(nref, NO, NO)))
			neighRef_update(nref->nn, nref->aggSqn, iid, &kn->kHash, kn->nextDesc ? kn->nextDesc->descSqn : kn->on->dc->descSqn, NULL);
		else
			neighRef_destroy(nref, YES);
	}
}


int purge_orig_router(struct orig_node *onlyOrig, struct neigh_node *onlyNeigh, LinkNode *onlyLink, IDM_T onlyUseless)
{
	TRACE_FUNCTION_CALL;
	int removed = 0;
	struct orig_node *on;
	struct avl_node *an = NULL;
	while ((on = onlyOrig) || (on = avl_iterate_item(&orig_tree, &an))) {

		if (
			(on->curr_rt_link) &&
			(!onlyUseless || (on->ogmMetric < UMETRIC_ROUTABLE)) &&
			(!onlyNeigh || on->curr_rt_link->k.linkDev->key.local == onlyNeigh) &&
			(!onlyLink || on->curr_rt_link == onlyLink)
			) {

			dbgf_track(DBGT_INFO, "only_orig=%s only_lndev=%s,%s onlyUseless=%d purging metric=%s neigh=%s link=%s dev=%s",
				onlyOrig ? cryptShaAsString(&onlyOrig->k.nodeId) : DBG_NIL,
				onlyLink ? ip6AsStr(&onlyLink->k.linkDev->key.llocal_ip) : DBG_NIL,
				onlyLink ? onlyLink->k.myDev->label_cfg.str : DBG_NIL,
				onlyUseless, umetric_to_human(on->ogmMetric),
				cryptShaAsString(&on->curr_rt_link->k.linkDev->key.local->local_id),
				ip6AsStr(&on->curr_rt_link->k.linkDev->key.llocal_ip),
				on->curr_rt_link->k.myDev->label_cfg.str);

			cb_route_change_hooks(DEL, on);
			on->curr_rt_link = NULL;

			removed++;
		}

		if (onlyOrig)
			break;
	}

	return removed;
}





void neigh_destroy(struct neigh_node *local)
{
	LinkDevNode *linkDev;

	dbgf_sys(DBGT_INFO, "purging local_id=%s curr_rx_packet=%d thisNeighsPacket=%d verified_link=%d",
		cryptShaAsString(&local->local_id), !!curr_rx_packet,
		(curr_rx_packet && curr_rx_packet->i.claimedKey == local->on->kn),
		(curr_rx_packet && curr_rx_packet->i.verifiedLink));

	if (curr_rx_packet && curr_rx_packet->i.claimedKey == local->on->kn)
		curr_rx_packet->i.verifiedLink = NULL;

	while ((linkDev = avl_first_item(&local->linkDev_tree)))
		purge_linkDevs(&linkDev->key, NULL, NO);


	assertion(-501135, (!local->linkDev_tree.items));
	assertion(-501135, (!local->orig_routes));
	assertion(-502465, (!local->best_rp_link));
	assertion(-502466, (!local->best_tp_link));


	IID_T iid;
	for (iid = 0; iid < local->neighIID4x_repos.max_free; iid++) {
		struct NeighRef_node *ref;
		if ((ref = iid_get_node_by_neighIID4x(&local->neighIID4x_repos, iid, NO, NULL)))
			neighRef_destroy(ref, YES);
	}


	purge_tx_task_tree(local, NULL, NULL, YES);

	local->on->neigh = NULL;
	local->on = NULL;

	if (local->linkKey)
		cryptKeyFree(&local->linkKey);

	free_internalNeighId(local->internalNeighId);

	avl_remove(&local_tree, &local->local_id, -300331);
	debugFree(local, -300333);
}





struct neigh_node *neigh_create(struct orig_node *on)
{
	struct neigh_node *nn = (on->neigh = debugMallocReset(sizeof(struct neigh_node), -300757));
	nn->local_id = on->k.nodeId;
	avl_insert(&local_tree, nn, -300758);

	AVL_INIT_TREE(nn->linkDev_tree, LinkDevNode, key.devIdx);

	nn->internalNeighId = allocate_internalNeighId(nn);

	struct dsc_msg_pubkey *pkey_msg = contents_data(on->dc, BMX_DSC_TLV_LINK_PUBKEY);

	if (pkey_msg)
		nn->linkKey = cryptPubKeyFromRaw(pkey_msg->key, cryptKeyLenByType(pkey_msg->type));

	nn->on = on;
	return nn;
}










void destroy_orig_node(struct orig_node *on)
{
	dbgf_sys(DBGT_INFO, "id=%s name=%s", cryptShaAsString(&on->k.nodeId), on->k.hostname);

	assertion(-502474, (on && on->dc && on->kn && on->dc->descSqn));
	assertion(-502475, (on->dc->on == on && on->dc->kn == on->kn && on->kn->on == on));
	assertion(-502180, IMPLIES(!terminating, on != myKey->on));
	assertion(-502476, (!on->neigh));

	purge_orig_router(on, NULL, NULL, NO);

	cb_plugin_hooks(PLUGIN_CB_DESCRIPTION_DESTROY, on);

	process_description_tlvs(NULL, on, NULL, on->dc, TLV_OP_DEL, FRAME_TYPE_PROCESS_ALL);

	if (on->trustedNeighsBitArray)
		debugFree(on->trustedNeighsBitArray, -300653);

	avl_remove(&orig_tree, &on->k.nodeId, -300200);
	cb_plugin_hooks(PLUGIN_CB_STATUS, NULL);

	uint16_t i;
	for (i = 0; i < plugin_data_registries[PLUGIN_DATA_ORIG]; i++) {
		assertion(-501269, (!on->plugin_data[i]));
	}

	on->kn->on = NULL;
	on->dc->on = NULL;

	if (on->kn->nextDesc)
		descContent_destroy(on->dc);
	else
		on->kn->nextDesc = on->dc;

	iid_free(NULL, on->__myIID4x, NO);

	debugFree(on, -300759);
}

void init_self(void)
{
	assertion(-502094, (my_NodeKey));
	assertion(-502477, (!myKey));

	struct key_credits friend_kc = {.dFriend = TYP_TRUST_LEVEL_IMPORT};
	struct dsc_msg_pubkey *msg = debugMallocReset(sizeof(struct dsc_msg_pubkey) +my_NodeKey->rawKeyLen, -300631);
	msg->type = my_NodeKey->rawKeyType;
	memcpy(msg->key, my_NodeKey->rawKey, my_NodeKey->rawKeyLen);

	struct content_node *cn = content_add_body((uint8_t*)msg, sizeof(struct dsc_msg_pubkey) +my_NodeKey->rawKeyLen, 0, 0, YES);

	myKey = keyNode_updCredits(&cn->chash, NULL, &friend_kc);

	debugFree(msg, -300600);
}

