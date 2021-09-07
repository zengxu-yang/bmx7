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

#define DEF_ATTACKED_NODES_DIR "/etc/bmx7/gatewayNodes"
#define ARG_ATTACKED_NODES_DIR "gatewayNodesDir"

#define DEF_NEXTHOP_TUN_NAME "bmxZero"
#define DEF_NEXTHOP_IP_TABLE 59
#define DEF_NEXTHOP_IP_RULE 59
#define DEF_NEXTHOP_IP_METRIC 1024

#define ARG_NEXTHOP_ROUTE_DROPPING "nexthopRouteDropping"
#define DEF_NEXTHOP_ROUTE_DROPPING 0
#define MIN_NEXTHOP_ROUTE_DROPPING 0
#define MAX_NEXTHOP_ROUTE_DROPPING 1

#define ARG_NEXTHOP_PRIMARY_IPS "nexthopPrimaryIps"
#define DEF_NEXTHOP_PRIMARY_IPS 0
#define MIN_NEXTHOP_PRIMARY_IPS 0
#define MAX_NEXTHOP_PRIMARY_IPS 1

#define ARG_NEXTHOP_DESC_DROPPING "nexthopDescDropping"
#define DEF_NEXTHOP_DESC_DROPPING 0
#define MIN_NEXTHOP_DESC_DROPPING 0
#define MAX_NEXTHOP_DESC_DROPPING 1

#define ARG_NEXTHOP_DESC_SQNS "nexthopDescSqns"
#define DEF_NEXTHOP_DESC_SQNS 0
#define MIN_NEXTHOP_DESC_SQNS 0
#define MAX_NEXTHOP_DESC_SQNS 1

#define ARG_NEXTHOP_DHASH_DROPPING "nexthopDhashDropping"
#define DEF_NEXTHOP_DHASH_DROPPING 0
#define MIN_NEXTHOP_DHASH_DROPPING 0
#define MAX_NEXTHOP_DHASH_DROPPING 1

#define ARG_NEXTHOP_OGM_DROPPING "nexthopOgmDropping"
#define DEF_NEXTHOP_OGM_DROPPING 0
#define MIN_NEXTHOP_OGM_DROPPING 0
#define MAX_NEXTHOP_OGM_DROPPING 1

#define ARG_NEXTHOP_OGM_METRICS "nexthopOgmMetrics"
#define DEF_NEXTHOP_OGM_METRICS 0
#define MIN_NEXTHOP_OGM_METRICS 0
#define MAX_NEXTHOP_OGM_METRICS 1

#define ARG_NEXTHOP_OGM_HASH "nexthopOgmHash"
#define DEF_NEXTHOP_OGM_HASH 0
#define MIN_NEXTHOP_OGM_HASH 0
#define MAX_NEXTHOP_OGM_HASH 10
