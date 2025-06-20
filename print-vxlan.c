/*
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that: (1) source code
 * distributions retain the above copyright notice and this paragraph
 * in its entirety, and (2) distributions including binary code include
 * the above copyright notice and this paragraph in its entirety in
 * the documentation or other materials provided with the distribution.
 * THIS SOFTWARE IS PROVIDED ``AS IS'' AND
 * WITHOUT ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, WITHOUT
 * LIMITATION, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS
 * FOR A PARTICULAR PURPOSE.
 *
 * Original code by Francesco Fondelli (francesco dot fondelli, gmail dot com)
 */

/* \summary: Virtual eXtensible Local Area Network (VXLAN) printer */

/* specification: RFC 7348 */

#include <config.h>

#include "netdissect-stdinc.h"

#define ND_LONGJMP_FROM_TCHECK
#include "netdissect.h"
#include "extract.h"

#define VXLAN_I     0x08 /* Instance Bit */

static const struct tok vxlan_flags [] = {
    { VXLAN_I, "I" },
    { 0, NULL }
};
#define VXLAN_HDR_LEN 8

/*
 * VXLAN header, RFC7348
 *               Virtual eXtensible Local Area Network (VXLAN): A Framework
 *               for Overlaying Virtualized Layer 2 Networks over Layer 3 Networks
 *
 *     0                   1                   2                   3
 *     0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
 *    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *    |R|R|R|R|I|R|R|R|            Reserved                           |
 *    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *    |                VXLAN Network Identifier (VNI) |   Reserved    |
 *    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 */

void
vxlan_print(netdissect_options *ndo, const u_char *bp, u_int length)
{
    uint8_t flags;

    ndo->ndo_protocol = "vxlan";
    nd_print_protocol_caps(ndo);
    ND_ICHECK_U(length, <, VXLAN_HDR_LEN);

    flags = GET_U_1(bp);
    bp += 1;
    ND_PRINT(", flags [%s] (0x%02x), ",
             bittok2str_nosep(vxlan_flags, "invalid", flags), flags);

    /* 1st Reserved */
    bp += 3;

    /*
     * RFC 7348 says that the I flag MUST be set.
     */
    if (flags & VXLAN_I)
        ND_PRINT("vni %u\n", GET_BE_U_3(bp));
    else
        ND_PRINT("ERROR: I flag not set\n");
    bp += 3;

    /* 2nd Reserved */
    ND_TCHECK_1(bp);
    bp += 1;

    ether_print(ndo, bp, length - VXLAN_HDR_LEN, ND_BYTES_AVAILABLE_AFTER(bp), NULL, NULL);

    return;

invalid:
    nd_print_invalid(ndo);
}
