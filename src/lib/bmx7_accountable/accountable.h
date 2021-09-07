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

#define DEF_ATTACKED_NODES_DIR "/etc/bmx7/acctNodes"
#define ARG_ATTACKED_NODES_DIR "acctNodesDir"
#define ARG_ACCT "acct"

#define DEF_ACCOUNTABLE_TUN_NAME "bmxZero"
#define DEF_ACCOUNTABLE_IP_TABLE 59
#define DEF_ACCOUNTABLE_IP_RULE 59
#define DEF_ACCOUNTABLE_IP_METRIC 1024

#define ARG_ACCOUNTABLE_ROUTE_DROPPING "accountableRouteDropping"
#define DEF_ACCOUNTABLE_ROUTE_DROPPING 0
#define MIN_ACCOUNTABLE_ROUTE_DROPPING 0
#define MAX_ACCOUNTABLE_ROUTE_DROPPING 1

#define ARG_ACCOUNTABLE_PRIMARY_IPS "accountablePrimaryIps"
#define DEF_ACCOUNTABLE_PRIMARY_IPS 0
#define MIN_ACCOUNTABLE_PRIMARY_IPS 0
#define MAX_ACCOUNTABLE_PRIMARY_IPS 1

#define ARG_ACCOUNTABLE_DESC_DROPPING "accountableDescDropping"
#define DEF_ACCOUNTABLE_DESC_DROPPING 0
#define MIN_ACCOUNTABLE_DESC_DROPPING 0
#define MAX_ACCOUNTABLE_DESC_DROPPING 1

#define ARG_ACCOUNTABLE_DESC_SQNS "accountableDescSqns"
#define DEF_ACCOUNTABLE_DESC_SQNS 0
#define MIN_ACCOUNTABLE_DESC_SQNS 0
#define MAX_ACCOUNTABLE_DESC_SQNS 1

#define ARG_ACCOUNTABLE_DHASH_DROPPING "accountableDhashDropping"
#define DEF_ACCOUNTABLE_DHASH_DROPPING 0
#define MIN_ACCOUNTABLE_DHASH_DROPPING 0
#define MAX_ACCOUNTABLE_DHASH_DROPPING 1

#define ARG_ACCOUNTABLE_OGM_DROPPING "accountableOgmDropping"
#define DEF_ACCOUNTABLE_OGM_DROPPING 0
#define MIN_ACCOUNTABLE_OGM_DROPPING 0
#define MAX_ACCOUNTABLE_OGM_DROPPING 1

#define ARG_ACCOUNTABLE_OGM_METRICS "accountableOgmMetrics"
#define DEF_ACCOUNTABLE_OGM_METRICS 0
#define MIN_ACCOUNTABLE_OGM_METRICS 0
#define MAX_ACCOUNTABLE_OGM_METRICS 1

#define ARG_ACCOUNTABLE_OGM_HASH "accountableOgmHash"
#define DEF_ACCOUNTABLE_OGM_HASH 0
#define MIN_ACCOUNTABLE_OGM_HASH 0
#define MAX_ACCOUNTABLE_OGM_HASH 10

#define ARG_JSON "json"
#define DEF_JSON 0
#define MAX_JSON 1
#define MIN_JSON 0
#define HLP_ARG_JSON        "use json"

uint32_t fields_dbg_table(struct ctrl_node *cn, uint16_t relevance, uint32_t data_size, uint8_t *data,
			  uint32_t min_msg_size, const struct field_format *format);
