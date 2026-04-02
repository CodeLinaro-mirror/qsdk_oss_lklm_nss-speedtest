/*
 * Copyright (c) Qualcomm Technologies, Inc. and/or its subsidiaries.
 * SPDX-License-Identifier: ISC
 */

/**
 * @file nss_udp_st_public.h
 *	NSS UDP ST Public definitions.
 */

#ifndef _NSS_UDP_ST_PUBLIC_H_
#define _NSS_UDP_ST_PUBLIC_H_

/**
 * @addtogroup nss_udp_st_public_subsystem
 * @{
 */

#include "nss_udp_st_drv.h"
#include "nss_udp_st_tx.h"
#include "nss_udp_st_rx.h"
#include "nss_udp_st_ip.h"
#ifdef NSS_UDP_ST_DRV_HW_OFFLOAD_ENABLE
#include "nss_udp_st_ppe.h"
#endif

/** @} */ /* end_addtogroup nss_udp_st_public_subsystem */

#endif /*_NSS_UDP_ST_PUBLIC_H_*/
