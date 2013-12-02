/*
 * Copyright (c) 2013, 2014 Cisco Systems, Inc.
 *
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

#ifndef NSH_H
#define NSH_H 1

#include <linux/types.h>
#include <asm/byteorder.h>


/**
 * struct nsh_bhdr - Network Service Base Header.
 * @o: Operations and Management Packet indicator bit
 * @c: If this bit is set then one or more contexts are in use.
 * @proto: IEEE Ethertypes to indicate the frame within.
 * @svc_idx: TTL functionality and location within service path.
 * @svc_path: To uniquely identify service path.
 */
struct nsh_base {
#if defined(__LITTLE_ENDIAN_BITFIELD)
	__u8	res:6,
		c:1,
		o:1;
#elif defined(__BIG_ENDIAN_BITFIELD)
	__u8	o:1,
		c:1,
		res:6;
#else
#error "Bitfield Endianess not defined."
#endif
	__u8	res1;
	__be16	proto;
	union {
		struct {
			__u8	svc_path[3];
			__u8	svc_idx;
		};
		__be32 b2;
	};
};

/**
 * struct nsh_ctx - Keeps track of NSH context data
 * @npc: NSH network platform context
 * @nsc: NSH network shared context
 * @spc: NSH service platform context
 * @ssc: NSH service shared context
 */
struct nsh_ctx {
	__be32 npc;
	__be32 nsc;
	__be32 spc;
	__be32 ssc;
};

/**
 * struct nshdr - Network Service header
 * @nsh_base: Network Service Base Header.
 * @nsh_ctx: Network Service Context Header.
 */
struct nshhdr {
	struct nsh_base b;
	struct nsh_ctx c;
};


#define ETH_P_NSH	0x894F /* Ethertype for NSH */
#define NSH_P_TEB	0x6558 /* Transparent Ethernet Bridging */
#define NSH_DST_PORT	6633   /* UDP Port for NSH on VXLAN */


#endif /* nsh.h */
