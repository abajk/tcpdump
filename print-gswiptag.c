/*
 * Copyright (c) 1988, 1989, 1990, 1991, 1992, 1993, 1994, 1995, 1996, 1997
 *	The Regents of the University of California.  All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that: (1) source code distributions
 * retain the above copyright notice and this paragraph in its entirety, (2)
 * distributions including binary code include the above copyright notice and
 * this paragraph in its entirety in the documentation or other materials
 * provided with the distribution, and (3) all advertising materials mentioning
 * features or use of this software display the following acknowledgement:
 * ``This product includes software developed by the University of California,
 * Lawrence Berkeley Laboratory and its contributors.'' Neither the name of
 * the University nor the names of its contributors may be used to endorse
 * or promote products derived from this software without specific prior
 * written permission.
 * THIS SOFTWARE IS PROVIDED ``AS IS'' AND WITHOUT ANY EXPRESS OR IMPLIED
 * WARRANTIES, INCLUDING, WITHOUT LIMITATION, THE IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE.
 */

/* \summary: Lantiq GSWIP Ethernet switches tag (4 bytes) printer */

#include <config.h>

#include "netdissect-stdinc.h"

#define ND_LONGJMP_FROM_TCHECK
#include "netdissect.h"
#include "addrtoname.h"
#include "extract.h"

#define GSWIP_EG_TAG_LEN	4

/* Egress fields */
/* Byte 0 */
#define GSWIP_EG_SPID_MASK	0x07
/* Byte 1 */
#define GSWIP_EG_CRCGEN_DIS	(1 << 7)
#define GSWIP_EG_DPID_MASK	0x07
/* Byte 2 */
#define GSWIP_EG_PORT_MAP_EN		(1 << 7)
#define GSWIP_EG_PORT_MAP_SEL		(1 << 6)
#define GSWIP_EG_LRN_DIS		(1 << 5)
#define GSWIP_EG_CLASS_EN		(1 << 4)
#define GSWIP_EG_CLASS_SHIFT		0
#define GSWIP_EG_CLASS_MASK		0x0f
/* Byte 3 */
#define GSWIP_EG_DPID_EN		(1 << 0)
#define GSWIP_EG_PORT_MAP_SHIFT		1
#define GSWIP_EG_PORT_MAP_MASK		0x7e

#define GSWIP_IG_TAG_LEN	8

/* Ingress fields */
/* Byte 0 */
#define GSWIP_IG_IPOFF_MASK		0x3f
/* Byte 1 */
#define GSWIP_IG_PORT_MAP_MASK		0xff
/* Byte 7 */
#define GSWIP_IG_SPPID_SHIFT		4
#define GSWIP_IG_SPPID_MASK		0x70

static void
gswip_tag_eg_print(netdissect_options *ndo, const u_char *bp)
{
	uint8_t tag[GSWIP_EG_TAG_LEN];
	unsigned int i;

	for (i = 0; i < GSWIP_EG_TAG_LEN; i++)
		tag[i] = GET_U_1(bp + i);

	ND_PRINT("GSWIP tag SPID: %d", (tag[0] & GSWIP_EG_SPID_MASK));
	ND_PRINT(", CRCGEN: %d", (tag[1] & GSWIP_EG_CRCGEN_DIS));
	ND_PRINT(", DPID: %d", (tag[1] & GSWIP_EG_SPID_MASK));
	ND_PRINT(", MAP_EN: %d", (tag[2] & GSWIP_EG_PORT_MAP_EN));
	ND_PRINT(", MAP_SEL: %d", (tag[2] & GSWIP_EG_PORT_MAP_SEL));
	ND_PRINT(", LRN_DIS: %d", (tag[2] & GSWIP_EG_LRN_DIS));
	ND_PRINT(", CLASS_EN: %d", (tag[2] & GSWIP_EG_CLASS_EN));
	ND_PRINT(", CLASS: %d", (tag[2] & GSWIP_EG_CLASS_MASK));
	ND_PRINT(", DPID_EN: %d", (tag[3] & GSWIP_EG_DPID_EN));
	ND_PRINT(", PORT_MAP: %d, ", (tag[3] & GSWIP_EG_PORT_MAP_MASK) >>
			GSWIP_EG_PORT_MAP_SHIFT);
}

static void
gswip_tag_ig_print(netdissect_options *ndo, const u_char *bp)
{
	uint8_t tag[GSWIP_IG_TAG_LEN];
	unsigned int i;

	for (i = 0; i < GSWIP_IG_TAG_LEN; i++)
		tag[i] = GET_U_1(bp + i);

	ND_PRINT("GSWIP tag IPOFF: %d ", (tag[0] & GSWIP_IG_IPOFF_MASK));
	ND_PRINT(", PORT_MAP: %d, ", (tag[1] & GSWIP_IG_PORT_MAP_MASK));
	ND_PRINT(", SPID: %d, ", (tag[7] & GSWIP_IG_SPPID_MASK) >>
			GSWIP_IG_SPPID_SHIFT);
}

void
gswip_tag_if_print(netdissect_options *ndo, const struct pcap_pkthdr *h,
		  const u_char *p)
{
	u_int caplen = h->caplen;
	u_int length = h->len;

	ndo->ndo_protocol = "gswip-tag";
	if (h->dir == PCAP_D_OUT) {
		ndo->ndo_ll_hdr_len +=
			ether_switch_tag_print(ndo, p, length, caplen,
					       gswip_tag_eg_print, GSWIP_EG_TAG_LEN);
	} else {
		ndo->ndo_ll_hdr_len +=
			ether_switch_tag_print(ndo, p, length, caplen,
					       gswip_tag_ig_print, GSWIP_IG_TAG_LEN);
	}
}
