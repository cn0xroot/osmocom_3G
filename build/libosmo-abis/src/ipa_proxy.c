#include "internal.h"

#include <stdio.h>
#include <stdbool.h>
#include <unistd.h>
#include <stdlib.h>
#include <errno.h>
#include <string.h>
#include <time.h>
#include <sys/fcntl.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <arpa/inet.h>

#include <osmocom/core/select.h>
#include <osmocom/core/bitvec.h>
#include <osmocom/gsm/tlv.h>
#include <osmocom/core/msgb.h>
#include <osmocom/core/logging.h>
#include <osmocom/core/talloc.h>
#include <osmocom/abis/e1_input.h>
#include <osmocom/abis/ipaccess.h>
#include <osmocom/core/socket.h>

#include <osmocom/abis/ipa.h>
#include <osmocom/vty/vty.h>
#include <osmocom/vty/command.h>

static void *tall_ipa_proxy_ctx;

/*
 * data structures used by the IPA VTY commands
 */
static LLIST_HEAD(ipa_instance_list);

enum ipa_proxy_instance_net_type {
	IPA_INSTANCE_T_NONE,
	IPA_INSTANCE_T_BIND,
	IPA_INSTANCE_T_CONNECT,
	IPA_INSTANCE_T_MAX
};

struct ipa_proxy_instance_net {
	char					*addr;
	uint16_t				port;
	enum ipa_proxy_instance_net_type	type;
};

struct ipa_proxy_instance {
	struct llist_head		head;
#define IPA_INSTANCE_NAME		16
	char				name[IPA_INSTANCE_NAME];
	struct ipa_proxy_instance_net	net;
	int				refcnt;
};

static LLIST_HEAD(ipa_proxy_route_list);

/* Several routes pointing to the same instances share this. */
struct ipa_proxy_route_shared {
	int					refcnt;

	/* this file descriptor is used to accept() new connections. */
	struct osmo_fd				bfd;

	struct {
		struct ipa_proxy_instance	*inst;
		struct bitvec			streamid_map;
		uint8_t				streamid_map_data[(0xff+1)/8];
		uint8_t				streamid[0xff + 1];
	} src;
	struct {
		struct ipa_proxy_instance	*inst;
		struct bitvec			streamid_map;
		uint8_t				streamid_map_data[(0xff+1)/8];
		uint8_t				streamid[0xff + 1];
	} dst;

	struct llist_head			conn_list;
};

/* One route is composed of two instances. */
struct ipa_proxy_route {
	struct llist_head			head;

	struct {
		uint8_t				streamid;
	} src;
	struct {
		uint8_t				streamid;
	} dst;

	struct ipa_proxy_route_shared		*shared;
};

enum ipa_conn_state {
	IPA_CONN_S_NONE,
	IPA_CONN_S_CONNECTING,
	IPA_CONN_S_CONNECTED,
	IPA_CONN_S_MAX
};

/* One route may forward more than one connection. */
struct ipa_proxy_conn {
	struct llist_head		head;

	struct ipa_server_conn		*src;
	struct ipa_client_conn		*dst;
	struct ipa_proxy_route		*route;
};

/*
 * socket callbacks used by IPA VTY commands
 */
static int ipa_sock_dst_cb(struct ipa_client_conn *link, struct msgb *msg)
{
	struct ipaccess_head *hh;
	struct ipa_proxy_conn *conn = link->data;

	LOGP(DLINP, LOGL_NOTICE, "received message from client side\n");

	hh = (struct ipaccess_head *)msg->data;
	/* check if we have a route for this message. */
	if (bitvec_get_bit_pos(
	     &conn->route->shared->dst.streamid_map,
	     hh->proto) != ONE) {
		LOGP(DLINP, LOGL_NOTICE, "we don't have a "
			"route for streamid 0x%x\n", hh->proto);
		msgb_free(msg);
		return 0;
	}
	/* mangle message, if required. */
	hh->proto = conn->route->shared->src.streamid[hh->proto];

	ipa_server_conn_send(conn->src, msg);
	return 0;
}

static int ipa_sock_src_cb(struct ipa_server_conn *peer, struct msgb *msg)
{
	struct ipaccess_head *hh;
	struct ipa_proxy_conn *conn = peer->data;

	LOGP(DLINP, LOGL_NOTICE, "received message from server side\n");

	hh = (struct ipaccess_head *)msg->data;
	/* check if we have a route for this message. */
	if (bitvec_get_bit_pos(&conn->route->shared->src.streamid_map,
			hh->proto) != ONE) {
		LOGP(DLINP, LOGL_NOTICE, "we don't have a "
			"route for streamid 0x%x\n", hh->proto);
		msgb_free(msg);
		return 0;
	}
	/* mangle message, if required. */
	hh->proto = conn->route->shared->dst.streamid[hh->proto];

	ipa_client_conn_send(conn->dst, msg);
	return 0;
}

static int
ipa_sock_src_accept_cb(struct ipa_server_link *link, int fd)
{
	struct ipa_proxy_route *route = link->data;
	struct ipa_proxy_conn *conn;

	conn = talloc_zero(tall_ipa_proxy_ctx, struct ipa_proxy_conn);
	if (conn == NULL) {
		LOGP(DLINP, LOGL_ERROR, "cannot allocate memory for "
				       "origin IPA\n");
		close(fd);
		return -ENOMEM;
	}
	conn->route = route;

	conn->src = ipa_server_conn_create(tall_ipa_proxy_ctx, link, fd,
					   ipa_sock_src_cb, NULL, conn);
	if (conn->src == NULL) {
		LOGP(DLINP, LOGL_ERROR, "could not create server peer: %s\n",
			strerror(errno));
		return -ENOMEM;
	}

	LOGP(DLINP, LOGL_NOTICE, "now trying to connect to destination\n");

	conn->dst = ipa_client_conn_create(NULL, NULL, 0,
					   route->shared->dst.inst->net.addr,
					   route->shared->dst.inst->net.port,
					   NULL,
					   ipa_sock_dst_cb,
					   NULL,
					   conn);
	if (conn->dst == NULL) {
		LOGP(DLINP, LOGL_ERROR, "could not create client: %s\n",
			strerror(errno));
		return -ENOMEM;
	}
	if (ipa_client_conn_open(conn->dst) < 0) {
		LOGP(DLINP, LOGL_ERROR, "could not start client: %s\n",
			strerror(errno));
		return -ENOMEM;
	}
	llist_add(&conn->head, &route->shared->conn_list);
	return 0;
}

/*
 * VTY commands for IPA
 */
static int __ipa_instance_add(struct vty *vty, int argc, const char *argv[])
{
	struct ipa_proxy_instance *ipi;
	enum ipa_proxy_instance_net_type type;
	struct in_addr addr;
	uint16_t port;

	if (argc < 4)
		return CMD_ERR_INCOMPLETE;

	llist_for_each_entry(ipi, &ipa_instance_list, head) {
		if (strncmp(ipi->name, argv[0], IPA_INSTANCE_NAME) != 0)
			continue;

		vty_out(vty, "%% instance `%s' already exists%s",
			ipi->name, VTY_NEWLINE);
		return CMD_WARNING;
	}
	if (strncmp(argv[1], "bind", IPA_INSTANCE_NAME) == 0)
		type = IPA_INSTANCE_T_BIND;
	else if (strncmp(argv[1], "connect", IPA_INSTANCE_NAME) == 0)
		type = IPA_INSTANCE_T_CONNECT;
	else
		return CMD_ERR_INCOMPLETE;

	if (inet_aton(argv[2], &addr) < 0) {
		vty_out(vty, "%% invalid address %s%s", argv[1], VTY_NEWLINE);
		return CMD_WARNING;
	}
	port = atoi(argv[3]);

	ipi = talloc_zero(tall_ipa_proxy_ctx, struct ipa_proxy_instance);
	if (ipi == NULL) {
		vty_out(vty, "%% can't allocate memory for new instance%s",
			VTY_NEWLINE);
		return CMD_WARNING;
	}
	strncpy(ipi->name, argv[0], IPA_INSTANCE_NAME);
	ipi->name[IPA_INSTANCE_NAME - 1] = '\0';
	ipi->net.type = type;
	ipi->net.addr = talloc_strdup(tall_ipa_proxy_ctx, argv[2]);
	ipi->net.port = port;
	llist_add_tail(&ipi->head, &ipa_instance_list);

	return CMD_SUCCESS;
}

DEFUN(ipa_instance_add, ipa_instance_add_cmd,
      "ipa instance NAME (bind|connect) IP tcp port PORT",
      "Bind or connect instance to address and port")
{
	return __ipa_instance_add(vty, argc, argv);
}

DEFUN(ipa_instance_del, ipa_instance_del_cmd,
      "no ipa instance NAME",
      "Delete instance to address and port")
{
	struct ipa_proxy_instance *ipi;

	if (argc < 1)
		return CMD_ERR_INCOMPLETE;

	llist_for_each_entry(ipi, &ipa_instance_list, head) {
		if (strncmp(ipi->name, argv[0], IPA_INSTANCE_NAME) != 0)
			continue;

		if (ipi->refcnt > 0) {
			vty_out(vty, "%% instance `%s' is in use%s",
			ipi->name, VTY_NEWLINE);
			return CMD_WARNING;
		}
		llist_del(&ipi->head);
		talloc_free(ipi);
		return CMD_SUCCESS;
	}
	vty_out(vty, "%% instance `%s' does not exist%s",
		ipi->name, VTY_NEWLINE);

	return CMD_WARNING;
}

DEFUN(ipa_instance_show, ipa_instance_show_cmd,
      "ipa instance show", "Show existing ipaccess proxy instances")
{
	struct ipa_proxy_instance *this;

	llist_for_each_entry(this, &ipa_instance_list, head) {
		vty_out(vty, "instance %s %s %s tcp port %u%s",
			this->name, this->net.addr,
			this->net.type == IPA_INSTANCE_T_BIND ?
				"bind" : "connect",
			this->net.port, VTY_NEWLINE);
	}
	return CMD_SUCCESS;
}

static int __ipa_route_add(struct vty *vty, int argc, const char *argv[])
{
	struct ipa_proxy_instance *ipi = vty->index;
	struct ipa_proxy_instance *src = NULL, *dst = NULL;
	uint32_t src_streamid, dst_streamid;
	struct ipa_proxy_route *route, *matching_route = NULL;
	struct ipa_proxy_route_shared *shared = NULL;
	int ret;

	if (argc < 4)
		return CMD_ERR_INCOMPLETE;

	llist_for_each_entry(ipi, &ipa_instance_list, head) {
		if (strncmp(ipi->name, argv[0], IPA_INSTANCE_NAME) == 0) {
			src = ipi;
			continue;
		}
		if (strncmp(ipi->name, argv[2], IPA_INSTANCE_NAME) == 0) {
			dst = ipi;
			continue;
		}
	}
	if (src == NULL) {
		vty_out(vty, "%% instance `%s' does not exists%s",
			argv[0], VTY_NEWLINE);
		return CMD_WARNING;
	}
	if (dst == NULL) {
		vty_out(vty, "%% instance `%s' does not exists%s",
			argv[2], VTY_NEWLINE);
		return CMD_WARNING;
	}
	if (src->net.type != IPA_INSTANCE_T_BIND) {
		vty_out(vty, "%% instance `%s' is not of bind type%s",
			argv[0], VTY_NEWLINE);
		return CMD_WARNING;
	}
	if (dst->net.type != IPA_INSTANCE_T_CONNECT) {
		vty_out(vty, "%% instance `%s' is not of connect type%s",
			argv[2], VTY_NEWLINE);
		return CMD_WARNING;
	}
	src_streamid = strtoul(argv[1], NULL, 16);
	if (src_streamid > 0xff) {
		vty_out(vty, "%% source streamid must be "
			     ">= 0x00 and <= 0xff%s", VTY_NEWLINE);
		return CMD_WARNING;
	}
	dst_streamid = strtoul(argv[3], NULL, 16);
	if (dst_streamid > 0xff) {
		vty_out(vty, "%% destination streamid must be "
			     ">= 0x00 and <= 0xff%s", VTY_NEWLINE);
		return CMD_WARNING;
	}
	llist_for_each_entry(route, &ipa_proxy_route_list, head) {
		if (route->shared->src.inst == src &&
		    route->shared->dst.inst == dst) {
			if (route->src.streamid == src_streamid &&
			    route->dst.streamid == dst_streamid) {
				vty_out(vty, "%% this route already exists%s",
					VTY_NEWLINE);
				return CMD_WARNING;
			}
			matching_route = route;
			break;
		}
	}
	/* new route for this configuration. */
	route = talloc_zero(tall_ipa_proxy_ctx, struct ipa_proxy_route);
	if (route == NULL) {
		vty_out(vty, "%% can't allocate memory for new route%s",
			VTY_NEWLINE);
		return CMD_WARNING;
	}
	route->src.streamid = src_streamid;
	route->dst.streamid = dst_streamid;

	if (matching_route != NULL) {
		/* there's already a master route for these configuration. */
		if (matching_route->shared->src.inst != src) {
			vty_out(vty, "%% route does not contain "
				     "source instance `%s'%s",
				     argv[0], VTY_NEWLINE);
			return CMD_WARNING;
		}
		if (matching_route->shared->dst.inst != dst) {
			vty_out(vty, "%% route does not contain "
				     "destination instance `%s'%s",
				     argv[2], VTY_NEWLINE);
			return CMD_WARNING;
		}
		/* use already existing shared routing information. */
		shared = matching_route->shared;
	} else {
		struct ipa_server_link *link;

		/* this is a brand new route, allocate shared routing info. */
		shared = talloc_zero(tall_ipa_proxy_ctx, struct ipa_proxy_route_shared);
		if (shared == NULL) {
			vty_out(vty, "%% can't allocate memory for "
				"new route shared%s", VTY_NEWLINE);
			return CMD_WARNING;
		}
		shared->src.streamid_map.data_len =
			sizeof(shared->src.streamid_map_data);
		shared->src.streamid_map.data =
			shared->src.streamid_map_data;
		shared->dst.streamid_map.data_len =
			sizeof(shared->dst.streamid_map_data);
		shared->dst.streamid_map.data =
			shared->dst.streamid_map_data;

		link = ipa_server_link_create(tall_ipa_proxy_ctx, NULL,
						"0.0.0.0",
						src->net.port,
						ipa_sock_src_accept_cb, route);
		if (link == NULL) {
			vty_out(vty, "%% can't bind instance `%s' to port%s",
				src->name, VTY_NEWLINE);
			return CMD_WARNING;
		}
		if (ipa_server_link_open(link) < 0) {
			vty_out(vty, "%% can't bind instance `%s' to port%s",
				src->name, VTY_NEWLINE);
			return CMD_WARNING;
		}
		INIT_LLIST_HEAD(&shared->conn_list);
	}
	route->shared = shared;
	src->refcnt++;
	route->shared->src.inst = src;
	dst->refcnt++;
	route->shared->dst.inst = dst;
	shared->src.streamid[src_streamid] = dst_streamid;
	shared->dst.streamid[dst_streamid] = src_streamid;
	ret = bitvec_set_bit_pos(&shared->src.streamid_map, src_streamid, ONE);
	if (ret < 0) {
		vty_out(vty, "%% bad bitmask (?)%s", VTY_NEWLINE);
		return CMD_WARNING;
	}
	ret = bitvec_set_bit_pos(&shared->dst.streamid_map, dst_streamid, ONE);
	if (ret < 0) {
		vty_out(vty, "%% bad bitmask (?)%s", VTY_NEWLINE);
		return CMD_WARNING;
	}
	shared->refcnt++;

	llist_add_tail(&route->head, &ipa_proxy_route_list);
	return CMD_SUCCESS;
}

DEFUN(ipa_route_add, ipa_route_add_cmd,
      "ipa route instance NAME streamid HEXNUM "
		"instance NAME streamid HEXNUM", "Add IPA route")
{
	return __ipa_route_add(vty, argc, argv);
}

DEFUN(ipa_route_del, ipa_route_del_cmd,
      "no ipa route instance NAME streamid HEXNUM "
		   "instance NAME streamid HEXNUM", "Delete IPA route")
{
	struct ipa_proxy_instance *ipi = vty->index;
	struct ipa_proxy_instance *src = NULL, *dst = NULL;
	uint32_t src_streamid, dst_streamid;
	struct ipa_proxy_route *route, *matching_route = NULL;
	struct ipa_proxy_conn *conn, *tmp;

	if (argc < 4)
		return CMD_ERR_INCOMPLETE;

	llist_for_each_entry(ipi, &ipa_instance_list, head) {
		if (strncmp(ipi->name, argv[0], IPA_INSTANCE_NAME) == 0) {
			src = ipi;
			continue;
		}
		if (strncmp(ipi->name, argv[2], IPA_INSTANCE_NAME) == 0) {
			dst = ipi;
			continue;
		}
	}
	if (src == NULL) {
		vty_out(vty, "%% instance `%s' does not exists%s",
			argv[0], VTY_NEWLINE);
		return CMD_WARNING;
	}
	if (dst == NULL) {
		vty_out(vty, "%% instance `%s' does not exists%s",
			argv[2], VTY_NEWLINE);
		return CMD_WARNING;
	}
	if (src->net.type != IPA_INSTANCE_T_BIND) {
		vty_out(vty, "%% instance `%s' is not of bind type%s",
			argv[0], VTY_NEWLINE);
		return CMD_WARNING;
	}
	if (dst->net.type != IPA_INSTANCE_T_CONNECT) {
		vty_out(vty, "%% instance `%s' is not of connect type%s",
			argv[2], VTY_NEWLINE);
		return CMD_WARNING;
	}
	src_streamid = strtoul(argv[1], NULL, 16);
	if (src_streamid > 0xff) {
		vty_out(vty, "%% source streamid must be "
			     ">= 0x00 and <= 0xff%s", VTY_NEWLINE);
		return CMD_WARNING;
	}
	dst_streamid = strtoul(argv[3], NULL, 16);
	if (dst_streamid > 0xff) {
		vty_out(vty, "%% destination streamid must be "
			     ">= 0x00 and <= 0xff%s", VTY_NEWLINE);
		return CMD_WARNING;
	}
	llist_for_each_entry(route, &ipa_proxy_route_list, head) {
		if (route->shared->src.inst == src &&
		    route->shared->dst.inst == dst &&
		    route->src.streamid == src_streamid &&
		    route->dst.streamid == dst_streamid) {
			matching_route = route;
			break;
		}
	}
	if (matching_route == NULL) {
		vty_out(vty, "%% no route with that configuration%s",
			VTY_NEWLINE);
		return CMD_WARNING;
	}
	/* delete this route from list. */
	llist_del(&matching_route->head);

	if (--matching_route->shared->refcnt == 0) {
		/* nobody else using this route, release all resources. */
		llist_for_each_entry_safe(conn, tmp,
				&matching_route->shared->conn_list, head) {
			ipa_server_conn_destroy(conn->src);
			llist_del(&conn->head);
			talloc_free(conn);
		}
		osmo_fd_unregister(&route->shared->bfd);
		close(route->shared->bfd.fd);
		route->shared->bfd.fd = -1;

		talloc_free(route->shared);
	} else {
		/* otherwise, revert the mapping that this route applies. */
		bitvec_set_bit_pos(&matching_route->shared->src.streamid_map,
				   src_streamid, ZERO);
		bitvec_set_bit_pos(&matching_route->shared->dst.streamid_map,
				   dst_streamid, ZERO);
		matching_route->shared->src.streamid[src_streamid] = 0x00;
		matching_route->shared->dst.streamid[dst_streamid] = 0x00;
	}
	matching_route->shared->src.inst->refcnt--;
	matching_route->shared->dst.inst->refcnt--;
	talloc_free(matching_route);

	return CMD_SUCCESS;
}

DEFUN(ipa_route_show, ipa_route_show_cmd,
      "ipa route show", "Show existing ipaccess proxy routes")
{
	struct ipa_proxy_route *this;

	llist_for_each_entry(this, &ipa_proxy_route_list, head) {
		vty_out(vty, "route instance %s streamid 0x%.2x "
			           "instance %s streamid 0x%.2x%s",
			this->shared->src.inst->name, this->src.streamid,
			this->shared->dst.inst->name, this->dst.streamid,
			VTY_NEWLINE);
	}
	return CMD_SUCCESS;
}

/*
 * Config for ipaccess-proxy
 */
DEFUN(ipa_cfg, ipa_cfg_cmd, "ipa", "Configure the ipaccess proxy")
{
	vty->index = NULL;
	vty->node = L_IPA_NODE;
	return CMD_SUCCESS;
}

/* all these below look like enable commands, but without the ipa prefix. */
DEFUN(ipa_route_cfg_add, ipa_route_cfg_add_cmd,
      "route instance NAME streamid HEXNUM "
	    "instance NAME streamid HEXNUM", "Add IPA route")
{
	return __ipa_route_add(vty, argc, argv);
}

DEFUN(ipa_instance_cfg_add, ipa_instance_cfg_add_cmd,
      "instance NAME (bind|connect) IP tcp port PORT",
      "Bind or connect instance to address and port")
{
	return __ipa_instance_add(vty, argc, argv);
}

struct cmd_node ipa_node = {
	L_IPA_NODE,
	"%s(config-ipa)# ",
	1,
};

static int ipa_cfg_write(struct vty *vty)
{
	bool heading = false;
	struct ipa_proxy_instance *inst;
	struct ipa_proxy_route *route;

	llist_for_each_entry(inst, &ipa_instance_list, head) {
		if (!heading) {
			vty_out(vty, "ipa%s", VTY_NEWLINE);
			heading = true;
		}
		vty_out(vty, " instance %s %s %s tcp port %u%s",
			inst->name,
			inst->net.type == IPA_INSTANCE_T_BIND ?
				"bind" : "connect",
			inst->net.addr,
			inst->net.port, VTY_NEWLINE);
	}
	llist_for_each_entry(route, &ipa_proxy_route_list, head) {
		vty_out(vty, " route instance %s streamid 0x%.2x "
				    "instance %s streamid 0x%.2x%s",
			route->shared->src.inst->name, route->src.streamid,
			route->shared->dst.inst->name, route->dst.streamid,
			VTY_NEWLINE);
	}
	return CMD_SUCCESS;
}

void ipa_proxy_vty_init(void)
{
	tall_ipa_proxy_ctx =
		talloc_named_const(libosmo_abis_ctx, 1, "ipa_proxy");

	install_element(ENABLE_NODE, &ipa_instance_add_cmd);
	install_element(ENABLE_NODE, &ipa_instance_del_cmd);
	install_element(ENABLE_NODE, &ipa_instance_show_cmd);
	install_element(ENABLE_NODE, &ipa_route_add_cmd);
	install_element(ENABLE_NODE, &ipa_route_del_cmd);
	install_element(ENABLE_NODE, &ipa_route_show_cmd);

	install_element(CONFIG_NODE, &ipa_cfg_cmd);
	install_node(&ipa_node, ipa_cfg_write);
	vty_install_default(L_IPA_NODE);
	install_element(L_IPA_NODE, &ipa_instance_cfg_add_cmd);
	install_element(L_IPA_NODE, &ipa_route_cfg_add_cmd);
}
