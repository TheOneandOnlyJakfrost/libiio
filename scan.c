// SPDX-License-Identifier: LGPL-2.1-or-later
/*
 * libiio - Library for interfacing industrial I/O (IIO) devices
 *
 * Copyright (C) 2016 Analog Devices, Inc.
 * Author: Paul Cercueil <paul.cercueil@analog.com>
 */

#include "iio-config.h"
#include "iio-private.h"

#include <errno.h>
#include <stdbool.h>
#include <string.h>

struct iio_scan_context {
	bool scan_usb;
	char **usb_opts;
	uint32_t usb_num;
	bool scan_network;
	char **network_opts;
	uint32_t network_num;
	bool scan_local;
	uint32_t local_num;
	char **local_opts;
};

const char * iio_context_info_get_description(
		const struct iio_context_info *info)
{
	return info->description;
}

const char * iio_context_info_get_uri(
		const struct iio_context_info *info)
{
	return info->uri;
}

ssize_t iio_scan_context_get_info_list(struct iio_scan_context *ctx,
		struct iio_context_info ***info)
{
	struct iio_scan_result scan_result = { 0, NULL };
	uint32_t i;

	if (WITH_LOCAL_BACKEND && ctx->scan_local) {
		int ret = local_context_scan(&scan_result);
		if (ret < 0) {
			if (scan_result.info)
				iio_context_info_list_free(scan_result.info);
			return ret;
		}
	}

	if (WITH_USB_BACKEND && ctx->scan_usb) {
		int ret;
		if (!ctx->usb_num) {
			ret = usb_context_scan(&scan_result, NULL);
		} else {
			for (i = 0; i < ctx->usb_num; i++) {
				ret = usb_context_scan(&scan_result, ctx->usb_opts[i]);
				if (ret < 0)
					break;
			}
		}
		if (ret < 0) {
			if (scan_result.info)
				iio_context_info_list_free(scan_result.info);
			return ret;
		}
	}

	if (HAVE_DNS_SD && ctx->scan_network) {
		int ret = dnssd_context_scan(&scan_result);
		if (ret < 0) {
			if (scan_result.info)
				iio_context_info_list_free(scan_result.info);
			return ret;
		}
	}

	*info = scan_result.info;

	return (ssize_t) scan_result.size;
}

void iio_context_info_list_free(struct iio_context_info **list)
{
	struct iio_context_info **it;

	if (!list)
		return;

	for (it = list; *it; it++) {
		struct iio_context_info *info = *it;

		free(info->description);
		free(info->uri);
		free(info);
	}

	free(list);
}

struct iio_context_info *
iio_scan_result_add(struct iio_scan_result *scan_result)
{
	struct iio_context_info **info;
	size_t size = scan_result->size;

	info = realloc(scan_result->info, (size + 2) * sizeof(*info));
	if (!info)
		return NULL;

	scan_result->info = info;
	scan_result->size = size + 1;

	/* Make sure iio_context_info_list_free won't overflow */
	info[size + 1] = NULL;

	info[size] = zalloc(sizeof(**info));
	if (!info[size])
		return NULL;

	return info[size];
}

struct iio_scan_context * iio_create_scan_context(
		const char *backend, unsigned int flags)
{
	struct iio_scan_context *ctx;
	char *ptr, *end;

	/* "flags" must be zero for now */
	if (flags != 0) {
		errno = EINVAL;
		return NULL;
	}

	ctx = calloc(1, sizeof(*ctx));
	if (!ctx) {
		errno = ENOMEM;
		return NULL;
	}

	if (!backend || strstr(backend, "local")) {
		ctx->scan_local = true;
		ptr = (char *)backend;
		while((ptr = strstr(ptr, "local="))) {
			ctx->local_opts = realloc(ctx->local_opts, (ctx->local_num + 1) * sizeof(char *));
			if (!ctx->local_opts)
				goto create_scan_fail;
			ctx->local_opts[ctx->local_num] = iio_strndup(ptr, sizeof("local=1234567890") - 1);
			if (!ctx->local_opts[ctx->local_num])
				goto create_scan_fail;
			ctx->local_num++;
			ptr++;
		}
	}

	if (!backend || strstr(backend, "usb")) {
		ctx->scan_usb = true;
		ptr = (char *)backend;
		while((ptr = strstr(ptr, "usb="))) {
			char *p1, *p2;

			p1 = strchr(ptr, ',');
			p2 = strchr(ptr,'\0');
			if ((p1 && ((size_t)(p1 - ptr) >= sizeof("usb=1234:5678"))) ||
			    (p2 && !p1 && ((size_t)(p2 - ptr) >= sizeof("usb=1234:5678"))))
				goto create_scan_fail;

			ctx->usb_opts = realloc(ctx->usb_opts, (ctx->usb_num + 1) * sizeof(char *));
			if (!ctx->usb_opts)
				goto create_scan_fail;
			ctx->usb_opts[ctx->usb_num] = iio_strndup(ptr, sizeof("usb=1234:5678") - 1);
			if (!ctx->usb_opts[ctx->usb_num])
				goto create_scan_fail;
			if ((end = strchr(ctx->usb_opts[ctx->usb_num], ',')))
				*end = '\0';
			ctx->usb_num++;
			ptr++;
		}
	}

	if (!backend || strstr(backend, "ip"))
		ctx->scan_network = true;

	return ctx;

create_scan_fail:
	iio_scan_context_destroy(ctx);
	errno = ENOMEM;
	return NULL;
}

void iio_scan_context_destroy(struct iio_scan_context *ctx)
{
	uint32_t i;

	if (!ctx)
		return;
	if (ctx->scan_local) {
		if (ctx->local_opts) {
			for (i = 0; i < ctx->local_num; i++)
				free(ctx->local_opts[i]);
			free(ctx->local_opts);
		}
	}
	if (ctx->scan_usb) {
		if (ctx->usb_opts) {
			for (i = 0; i < ctx->usb_num; i++)
				free(ctx->usb_opts[i]);
			free(ctx->usb_opts);
		}
	}
	free(ctx);
}

struct iio_scan_block {
	struct iio_scan_context *ctx;
	struct iio_context_info **info;
	ssize_t ctx_cnt;
};

ssize_t iio_scan_block_scan(struct iio_scan_block *blk)
{
	iio_context_info_list_free(blk->info);
	blk->info = NULL;
	blk->ctx_cnt = iio_scan_context_get_info_list(blk->ctx, &blk->info);
	return blk->ctx_cnt;
}

struct iio_context_info *iio_scan_block_get_info(
		struct iio_scan_block *blk, unsigned int index)
{
	if (!blk->info || (ssize_t)index >= blk->ctx_cnt) {
		errno = EINVAL;
		return NULL;
	}
	return blk->info[index];
}

struct iio_scan_block *iio_create_scan_block(
		const char *backend, unsigned int flags)
{
	struct iio_scan_block *blk;

	blk = calloc(1, sizeof(*blk));
	if (!blk) {
		errno = ENOMEM;
		return NULL;
	}

	blk->ctx = iio_create_scan_context(backend, flags);
	if (!blk->ctx) {
		free(blk);
		return NULL;
	}

	return blk;
}

void iio_scan_block_destroy(struct iio_scan_block *blk)
{
	iio_context_info_list_free(blk->info);
	iio_scan_context_destroy(blk->ctx);
	free(blk);
}
