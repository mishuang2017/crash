/* net.c - core analysis suite
 *
 * Copyright (C) 1999, 2000, 2001, 2002 Mission Critical Linux, Inc.
 * Copyright (C) 2002-2016 David Anderson
 * Copyright (C) 2002-2016 Red Hat, Inc. All rights reserved.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 */

#include "defs.h"
#include <netinet/in.h>
#include <netdb.h>
#include <net/if_arp.h>
#include <arpa/inet.h>

/* cmi@nvidia.com */
extern void print_struct(char *, ulong);
void show_eswitch(ulong esw);
void show_namespace(ulong mlx5_flow_steering);
void show_mdev(ulong mdev);
void show_mlx(ulong net_addr);
void show_tcf_proto(ulong tcf_proto, int print);
int centos72(void);
int kernel49(void);
int centos(void);
void show_ingress(ulong net_addr);
void show_hash(ulong a, char *opt_s, char *opt_m, int print, int offset);
void show_hash_miniflow(ulong a, char *opt_s, char *opt_m, int print, int offset);

/*
 *  Cache values we need that can change based on OS version, or any other
 *  variables static to this file.  These are setup in net_init().  Dump 
 *  the table during runtime via "help -n".
 */
struct net_table {
	ulong flags;
        char *netdevice;    /* name of net device */
	char *dev_name_t;   /* readmem ID's */
        char *dev_type_t;
	char *dev_addr_t;
	long dev_name;
	long dev_next;
	long dev_type;
	long dev_addr_len;
	long dev_ip_ptr;
	long in_device_ifa_list;
	long in_ifaddr_ifa_next;
	long in_ifaddr_ifa_address;
	int net_device_name_index;
} net_table = { 0 };

struct net_table *net = &net_table;

#define NETDEV_INIT       (0x1)
#define STRUCT_DEVICE     (0x2)
#define STRUCT_NET_DEVICE (0x4)
#define SOCK_V1           (0x8)
#define SOCK_V2           (0x10)
#define NO_INET_SOCK      (0x20)

#define	DEV_NAME_MAX	100
struct devinfo {
	char		dev_name[DEV_NAME_MAX];
	unsigned char	dev_addr_len;
	short		dev_type;
};

#define BYTES_IP_ADDR	15	/* bytes to print IP addr (xxx.xxx.xxx.xxx) */
#define BYTES_PORT_NUM	5	/* bytes to print port number */
/* bytes needed for <ip address>:<port> notation */
#define BYTES_IP_TUPLE	(BYTES_IP_ADDR + BYTES_PORT_NUM + 1)

static void show_net_devices(ulong);
static void show_net_devices_v2(ulong);
static void show_net_devices_v3(ulong);
static void print_neighbour_q(ulong, int);
static void get_netdev_info(ulong, struct devinfo *);
static void get_device_name(ulong, char *);
static long get_device_address(ulong, char **, long);
static void get_device_ip6_address(ulong, char **, long);
static void get_sock_info(ulong, char *);
static void dump_arp(void);
static void arp_state_to_flags(unsigned char);
static void dump_ether_hw(unsigned char *, int);
static void dump_sockets(ulong, struct reference *);
static int  sym_socket_dump(ulong, int, int, ulong, struct reference *);
static void dump_hw_addr(unsigned char *, int);
static char *dump_in6_addr_port(uint16_t *, uint16_t, char *, int *);


#define MK_TYPE_T(f,s,m)						\
do {									\
	(f) = malloc(strlen(s) + strlen(m) + 2);			\
	if ((f) == NULL) {						\
		error(WARNING, "malloc fail for type %s.%s", (s), (m));	\
	} else {							\
		sprintf((f), "%s %s", (s), (m));			\
	}								\
} while(0)

void
net_init(void)
{
	/*
	 * Note the order of the following checks.  The device struct was
	 * renamed to net_device in 2.3, but there may be another struct
	 * called 'device' so we check for the new one first.
	 */
	STRUCT_SIZE_INIT(net_device, "net_device");

	if (VALID_STRUCT(net_device)) {
		net->netdevice = "net_device";
		net->dev_next = MEMBER_OFFSET_INIT(net_device_next,
			"net_device", "next");
		net->dev_name = MEMBER_OFFSET_INIT(net_device_name, 
			"net_device", "name");
		net->dev_type = MEMBER_OFFSET_INIT(net_device_type,
			"net_device", "type");
                net->dev_addr_len = MEMBER_OFFSET_INIT(net_device_addr_len,
			"net_device", "addr_len");
		net->dev_ip_ptr = MEMBER_OFFSET_INIT(net_device_ip_ptr,
			"net_device", "ip_ptr");
		MEMBER_OFFSET_INIT(net_device_dev_list, "net_device", "dev_list");
		MEMBER_OFFSET_INIT(net_device_ip6_ptr, "net_device", "ip6_ptr");
		MEMBER_OFFSET_INIT(inet6_dev_addr_list, "inet6_dev", "addr_list");
		MEMBER_OFFSET_INIT(inet6_ifaddr_addr, "inet6_ifaddr", "addr");
		MEMBER_OFFSET_INIT(inet6_ifaddr_if_list, "inet6_ifaddr", "if_list");
		MEMBER_OFFSET_INIT(inet6_ifaddr_if_next, "inet6_ifaddr", "if_next");
		MEMBER_OFFSET_INIT(in6_addr_in6_u, "in6_addr", "in6_u");

		MEMBER_OFFSET_INIT(net_dev_base_head, "net", "dev_base_head");
		ARRAY_LENGTH_INIT(net->net_device_name_index,
			net_device_name, "net_device.name", NULL, sizeof(char));
		net->flags |= (NETDEV_INIT|STRUCT_NET_DEVICE);
	} else {
		STRUCT_SIZE_INIT(device, "device");
		if (VALID_STRUCT(device)) {
			net->netdevice = "device";
			net->dev_next = MEMBER_OFFSET_INIT(device_next, 
				"device", "next");
			net->dev_name = MEMBER_OFFSET_INIT(device_name, 
				"device", "name");
	                net->dev_type = MEMBER_OFFSET_INIT(device_type, 
				"device", "type");
			net->dev_ip_ptr = MEMBER_OFFSET_INIT(device_ip_ptr, 
				"device", "ip_ptr");
	                net->dev_addr_len = MEMBER_OFFSET_INIT(device_addr_len, 
				"device", "addr_len");
			net->flags |= (NETDEV_INIT|STRUCT_DEVICE);
		} else 
			error(WARNING, 
				"net_init: unknown device type for net device");
	}
	if (VALID_MEMBER(task_struct_nsproxy))
		MEMBER_OFFSET_INIT(nsproxy_net_ns, "nsproxy", "net_ns");

	if (net->flags & NETDEV_INIT) {
		MK_TYPE_T(net->dev_name_t, net->netdevice, "name");
		MK_TYPE_T(net->dev_type_t, net->netdevice, "type");
		MK_TYPE_T(net->dev_addr_t, net->netdevice, "addr_len");

		MEMBER_OFFSET_INIT(socket_sk, "socket", "sk");
		MEMBER_OFFSET_INIT(neighbour_next, "neighbour", "next");
        	MEMBER_OFFSET_INIT(neighbour_primary_key,  
			"neighbour", "primary_key");
        	MEMBER_OFFSET_INIT(neighbour_ha, "neighbour", "ha");
        	MEMBER_OFFSET_INIT(neighbour_dev, "neighbour", "dev");
        	MEMBER_OFFSET_INIT(neighbour_nud_state,  
			"neighbour", "nud_state");
		MEMBER_OFFSET_INIT(neigh_table_nht_ptr, "neigh_table", "nht");
		if (VALID_MEMBER(neigh_table_nht_ptr)) {
			MEMBER_OFFSET_INIT(neigh_table_hash_mask,
				"neigh_hash_table", "hash_mask");
			MEMBER_OFFSET_INIT(neigh_table_hash_shift,
				"neigh_hash_table", "hash_shift");
			MEMBER_OFFSET_INIT(neigh_table_hash_buckets,
				"neigh_hash_table", "hash_buckets");
		} else {
			MEMBER_OFFSET_INIT(neigh_table_hash_buckets,
				"neigh_table", "hash_buckets");
			MEMBER_OFFSET_INIT(neigh_table_hash_mask,
				"neigh_table", "hash_mask");
		}
		MEMBER_OFFSET_INIT(neigh_table_key_len,
			"neigh_table", "key_len");

        	MEMBER_OFFSET_INIT(in_device_ifa_list,  
			"in_device", "ifa_list");
        	MEMBER_OFFSET_INIT(in_ifaddr_ifa_next,  
			"in_ifaddr", "ifa_next");
        	MEMBER_OFFSET_INIT(in_ifaddr_ifa_address, 
			"in_ifaddr", "ifa_address");

		STRUCT_SIZE_INIT(sock, "sock");

                MEMBER_OFFSET_INIT(sock_family, "sock", "family");
		if (VALID_MEMBER(sock_family)) {
                	MEMBER_OFFSET_INIT(sock_daddr, "sock", "daddr");
                	MEMBER_OFFSET_INIT(sock_rcv_saddr, "sock", "rcv_saddr");
                	MEMBER_OFFSET_INIT(sock_dport, "sock", "dport");
                	MEMBER_OFFSET_INIT(sock_sport, "sock", "sport");
                	MEMBER_OFFSET_INIT(sock_num, "sock", "num");
                	MEMBER_OFFSET_INIT(sock_type, "sock", "type");
			net->flags |= SOCK_V1;

		} else {
			/*
			 * struct sock {
        		 *	struct sock_common      __sk_common;
			 * #define sk_family __sk_common.skc_family
			 *      ...
			 */
			MEMBER_OFFSET_INIT(sock_common_skc_family,
				"sock_common", "skc_family");
			MEMBER_OFFSET_INIT(sock_sk_type, "sock", "sk_type");
			MEMBER_OFFSET_INIT(sock_sk_common, "sock", "__sk_common");
			MEMBER_OFFSET_INIT(sock_common_skc_v6_daddr, "sock_common", "skc_v6_daddr");
			MEMBER_OFFSET_INIT(sock_common_skc_v6_rcv_saddr, "sock_common", "skc_v6_rcv_saddr");
			/*
			 *  struct inet_sock {
        		 *	struct sock       sk;
        		 *	struct ipv6_pinfo *pinet6;
        		 *	struct inet_opt   inet;
			 *  };
			 */
			STRUCT_SIZE_INIT(inet_sock, "inet_sock");
			STRUCT_SIZE_INIT(socket, "socket");

			if (STRUCT_EXISTS("inet_opt")) {
				MEMBER_OFFSET_INIT(inet_sock_inet, "inet_sock", "inet");
				MEMBER_OFFSET_INIT(inet_opt_daddr, "inet_opt", "daddr");
				MEMBER_OFFSET_INIT(inet_opt_rcv_saddr, "inet_opt", "rcv_saddr");
				MEMBER_OFFSET_INIT(inet_opt_dport, "inet_opt", "dport");
				MEMBER_OFFSET_INIT(inet_opt_sport, "inet_opt", "sport");
				MEMBER_OFFSET_INIT(inet_opt_num, "inet_opt", "num");
			} else {	/* inet_opt moved to inet_sock */
				ASSIGN_OFFSET(inet_sock_inet) = 0;
				if (MEMBER_EXISTS("inet_sock", "daddr")) {
					MEMBER_OFFSET_INIT(inet_opt_daddr, "inet_sock", "daddr");
					MEMBER_OFFSET_INIT(inet_opt_rcv_saddr, "inet_sock", "rcv_saddr");
					MEMBER_OFFSET_INIT(inet_opt_dport, "inet_sock", "dport");
					MEMBER_OFFSET_INIT(inet_opt_sport, "inet_sock", "sport");
					MEMBER_OFFSET_INIT(inet_opt_num, "inet_sock", "num");
				} else if (MEMBER_EXISTS("inet_sock", "inet_daddr")) {
					MEMBER_OFFSET_INIT(inet_opt_daddr, "inet_sock", "inet_daddr");
					MEMBER_OFFSET_INIT(inet_opt_rcv_saddr, "inet_sock", "inet_rcv_saddr");
					MEMBER_OFFSET_INIT(inet_opt_dport, "inet_sock", "inet_dport");
					MEMBER_OFFSET_INIT(inet_opt_sport, "inet_sock", "inet_sport");
					MEMBER_OFFSET_INIT(inet_opt_num, "inet_sock", "inet_num");
				} else if ((MEMBER_OFFSET("inet_sock", "sk") == 0) &&
				    (MEMBER_OFFSET("sock", "__sk_common") == 0)) {
					MEMBER_OFFSET_INIT(inet_opt_daddr, "sock_common", "skc_daddr");
					if (INVALID_MEMBER(inet_opt_daddr))
						ANON_MEMBER_OFFSET_INIT(inet_opt_daddr, "sock_common", 
							"skc_daddr");
					MEMBER_OFFSET_INIT(inet_opt_rcv_saddr, "sock_common", "skc_rcv_saddr");
					if (INVALID_MEMBER(inet_opt_rcv_saddr))
						ANON_MEMBER_OFFSET_INIT(inet_opt_rcv_saddr, "sock_common",
							"skc_rcv_saddr");
					MEMBER_OFFSET_INIT(inet_opt_dport, "inet_sock", "inet_dport");
					if (INVALID_MEMBER(inet_opt_dport)) {
						MEMBER_OFFSET_INIT(inet_opt_dport, "sock_common", 
							"skc_dport");
						if (INVALID_MEMBER(inet_opt_dport))
							ANON_MEMBER_OFFSET_INIT(inet_opt_dport, "sock_common", 
								"skc_dport");
					}
					MEMBER_OFFSET_INIT(inet_opt_sport, "inet_sock", "inet_sport");
					MEMBER_OFFSET_INIT(inet_opt_num, "inet_sock", "inet_num");
					if (INVALID_MEMBER(inet_opt_num)) {
						MEMBER_OFFSET_INIT(inet_opt_num, "sock_common", "skc_num");
						if (INVALID_MEMBER(inet_opt_num))
							ANON_MEMBER_OFFSET_INIT(inet_opt_num, "sock_common", 
							"skc_num");
					}
				}
			}	

			if (VALID_STRUCT(inet_sock) && 
			    INVALID_MEMBER(inet_sock_inet)) {
				/*
				 *  gdb can't seem to figure out the inet_sock
				 *  in later 2.6 kernels, returning this:
				 *
				 *  struct inet_sock {
				 *      <no data fields>
			         *  }
				 *  
				 *  It does know the struct size, so kludge it
			         *  to subtract the size of the inet_opt struct
				 *  from the size of the containing inet_sock.
				 */
				net->flags |= NO_INET_SOCK;
				ASSIGN_OFFSET(inet_sock_inet) = 
				    SIZE(inet_sock) - STRUCT_SIZE("inet_opt");
			}

			/* 
			 *  If necessary, set inet_sock size and inet_sock_inet offset,
			 *  accounting for the configuration-dependent, intervening,
			 *  struct ipv6_pinfo pointer located in between the sock and 
			 *  inet_opt members of the inet_sock.
			 */
			if (!VALID_STRUCT(inet_sock)) 
			{
				if (symbol_exists("tcpv6_protocol") && 
				    symbol_exists("udpv6_protocol")) {
					ASSIGN_SIZE(inet_sock) = SIZE(sock) + 
						sizeof(void *) + STRUCT_SIZE("inet_opt");
					ASSIGN_OFFSET(inet_sock_inet) = SIZE(sock) + 
						sizeof(void *);
				} else {
					ASSIGN_SIZE(inet_sock) = SIZE(sock) + 
						STRUCT_SIZE("inet_opt");
					ASSIGN_OFFSET(inet_sock_inet) = SIZE(sock);
				}
			}

			MEMBER_OFFSET_INIT(ipv6_pinfo_rcv_saddr, "ipv6_pinfo", "rcv_saddr");
			MEMBER_OFFSET_INIT(ipv6_pinfo_daddr, "ipv6_pinfo", "daddr");
			STRUCT_SIZE_INIT(in6_addr, "in6_addr");
			MEMBER_OFFSET_INIT(socket_alloc_vfs_inode, "socket_alloc", "vfs_inode");

			net->flags |= SOCK_V2;
		}
	}	
}

/*
 * The net command...
 */

#define NETOPTS	  "N:asSR:xdn"
#define s_FLAG FOREACH_s_FLAG
#define S_FLAG FOREACH_S_FLAG
#define x_FLAG FOREACH_x_FLAG
#define d_FLAG FOREACH_d_FLAG

#define NET_REF_FOUND             (0x1)
#define NET_REF_HEXNUM            (0x2)
#define NET_REF_DECNUM            (0x4)
#define NET_TASK_HEADER_PRINTED   (0x8)
#define NET_SOCK_HEADER_PRINTED  (0x10)
#define NET_REF_FOUND_ITEM       (0x20)

#define NET_REFERENCE_CHECK(X)   (X)
#define NET_REFERENCE_FOUND(X)   ((X) && ((X)->cmdflags & NET_REF_FOUND))

void
cmd_net(void)
{
	int c;
	ulong sflag, nflag, aflag;
	ulong value;
	ulong task;
	struct task_context *tc = NULL;
	struct in_addr in_addr;
	struct reference reference, *ref;

	if (!(net->flags & NETDEV_INIT)) 
		error(FATAL, "net subsystem not initialized!");

	ref = NULL;
	sflag = nflag = aflag = 0;
	task = pid_to_task(0);

	while ((c = getopt(argcnt, args, NETOPTS)) != EOF) {
		switch (c) {
		case 'R':
			if (ref)
				error(INFO, "only one -R option allowed\n");
			else {
				ref = &reference;
				BZERO(ref, sizeof(struct reference));
				ref->str = optarg;
			}
			break;

		case 'a':
			dump_arp();
			aflag++;
			break;

		case 'N':
			value = stol(optarg, FAULT_ON_ERROR, NULL);
			in_addr.s_addr = (in_addr_t)value;
			fprintf(fp, "%s\n", inet_ntoa(in_addr));
			return;

		case 's':
			if (sflag & S_FLAG)
				error(INFO, 
				    "only one -s or -S option allowed\n");
			else
				sflag |= s_FLAG;
		        break;

		case 'S':
			if (sflag & s_FLAG)
				error(INFO, 
				    "only one -s or -S option allowed\n");
			else
				sflag |= S_FLAG;
            		break;

		case 'x':
			if (sflag & d_FLAG)
				error(FATAL,
					"-d and -x are mutually exclusive\n");
			sflag |= x_FLAG;
			break;

		case 'd':
			if (sflag & x_FLAG)
				error(FATAL,
					"-d and -x are mutually exclusive\n");
			sflag |= d_FLAG;
			break;

		case 'n':
			nflag = 1;
			task = CURRENT_TASK();
			if (args[optind]) {
				switch (str_to_context(args[optind],
					 &value, &tc)) {
				case STR_PID:
				case STR_TASK:
					task = tc->task;
					break;
				case STR_INVALID:
					error(FATAL, "invalid task or pid value: %s\n", args[optind]);
				}
			}
			break;

		default:
			argerrs++;
			break;
		}
	}

	if (argerrs) 
		cmd_usage(pc->curcmd, SYNOPSIS);

	if (sflag & (s_FLAG|S_FLAG))
		dump_sockets(sflag, ref);
	else {
		if ((argcnt == 1) || nflag)
			show_net_devices(task);
		else if (!aflag)
			cmd_usage(pc->curcmd, SYNOPSIS);
	}
}

/*
 *  Just display the address and name of each net device.
 */

static void
show_net_devices(ulong task)
{
	ulong next;
	long flen;
	char *buf;
	long buflen = BUFSIZE;

	if (symbol_exists("dev_base_head")) {
		show_net_devices_v2(task);
		return;
	} else if (symbol_exists("init_net")) {
		show_net_devices_v3(task);
		return;
	}

	if (!symbol_exists("dev_base"))
		error(FATAL, "dev_base, dev_base_head or init_net do not exist!\n");

	get_symbol_data("dev_base", sizeof(void *), &next);

	if (!net->netdevice || !next)
		return;

	buf = GETBUF(buflen);
	flen = MAX(VADDR_PRLEN, strlen(net->netdevice));

	fprintf(fp, "%s  NAME       IP ADDRESS(ES)\n",
		mkstring(upper_case(net->netdevice, buf), 
			flen, CENTER|LJUST, NULL));

	do {
                fprintf(fp, "%s  ", 
                    mkstring(buf, flen, CENTER|RJUST|LONG_HEX, MKSTR(next)));

		get_device_name(next, buf);
		fprintf(fp, "%-10s ", buf);

		get_device_address(next, &buf, buflen);
		get_device_ip6_address(next, &buf, buflen);
		fprintf(fp, "%s\n", buf);

        	readmem(next+net->dev_next, KVADDR, &next, 
			sizeof(void *), "(net_)device.next", FAULT_ON_ERROR);
	} while (next);

	FREEBUF(buf);
}

static void
show_net_devices_v2(ulong task)
{
	struct list_data list_data, *ld;
	char *net_device_buf;
	char *buf;
	long buflen = BUFSIZE;
	int ndevcnt, i;
	long flen;

	if (!net->netdevice) /* initialized in net_init() */
		return;

	buf = GETBUF(buflen);
	flen = MAX(VADDR_PRLEN, strlen(net->netdevice));

	fprintf(fp, "%s  NAME       IP ADDRESS(ES)\n",
		mkstring(upper_case(net->netdevice, buf), 
			flen, CENTER|LJUST, NULL));

	net_device_buf = GETBUF(SIZE(net_device));

	ld =  &list_data;
	BZERO(ld, sizeof(struct list_data));
	ld->flags |= LIST_ALLOCATE;
	get_symbol_data("dev_base_head", sizeof(void *), &ld->start);
	ld->end = symbol_value("dev_base_head");
	ld->list_head_offset = OFFSET(net_device_dev_list);

	ndevcnt = do_list(ld);

	for (i = 0; i < ndevcnt; ++i) {
		readmem(ld->list_ptr[i], KVADDR, net_device_buf,
			SIZE(net_device), "net_device buffer",
			FAULT_ON_ERROR);

                fprintf(fp, "%s  ",
			mkstring(buf, flen, CENTER|RJUST|LONG_HEX,
			MKSTR(ld->list_ptr[i])));

		get_device_name(ld->list_ptr[i], buf);
		fprintf(fp, "%-10s ", buf);

		get_device_address(ld->list_ptr[i], &buf, buflen);
		get_device_ip6_address(ld->list_ptr[i], &buf, buflen);
		fprintf(fp, "%s\n", buf);
	}
	
	FREEBUF(ld->list_ptr);
	FREEBUF(net_device_buf);
	FREEBUF(buf);
}

static void
show_net_devices_v3(ulong task)
{
	ulong nsproxy_p, net_ns_p;
	struct list_data list_data, *ld;
	char *net_device_buf;
	char *buf;
	long buflen = BUFSIZE;
	int ndevcnt, i;
	long flen;

	if (!net->netdevice) /* initialized in net_init() */
		return;

	buf = GETBUF(buflen);
	flen = MAX(VADDR_PRLEN, strlen(net->netdevice));

	fprintf(fp, "%s  NAME       IP ADDRESS(ES)\n",
		mkstring(upper_case(net->netdevice, buf), 
			flen, CENTER|LJUST, NULL));

	net_device_buf = GETBUF(SIZE(net_device));

	ld =  &list_data;
	BZERO(ld, sizeof(struct list_data));
	ld->flags |= LIST_ALLOCATE;
	if (VALID_MEMBER(nsproxy_net_ns)) {
		readmem(task + OFFSET(task_struct_nsproxy), KVADDR, &nsproxy_p,
			sizeof(ulong), "task_struct.nsproxy", FAULT_ON_ERROR);
		if (!readmem(nsproxy_p + OFFSET(nsproxy_net_ns), KVADDR, &net_ns_p,
			sizeof(ulong), "nsproxy.net_ns", RETURN_ON_ERROR|QUIET))
			error(FATAL, "cannot determine net_namespace location!\n");
	} else
		net_ns_p = symbol_value("init_net");
	ld->start = ld->end = net_ns_p + OFFSET(net_dev_base_head);
	ld->list_head_offset = OFFSET(net_device_dev_list);

	ndevcnt = do_list(ld);

	/*
	 *  Skip the first entry (init_net).
	 */
	for (i = 1; i < ndevcnt; ++i) {
		readmem(ld->list_ptr[i], KVADDR, net_device_buf,
			SIZE(net_device), "net_device buffer",
			FAULT_ON_ERROR);

                fprintf(fp, "%s  ",
			mkstring(buf, flen, CENTER|RJUST|LONG_HEX,
			MKSTR(ld->list_ptr[i])));

		get_device_name(ld->list_ptr[i], buf);
		fprintf(fp, "%-10s ", buf);

		get_device_address(ld->list_ptr[i], &buf, buflen);
		get_device_ip6_address(ld->list_ptr[i], &buf, buflen);
		fprintf(fp, "%s\n", buf);
	}
	
	FREEBUF(ld->list_ptr);
	FREEBUF(net_device_buf);
	FREEBUF(buf);
}

/*
 * Perform the actual work of dumping the ARP table...
 */
#define ARP_HEADING \
	"NEIGHBOUR        IP ADDRESS      HW TYPE    HW ADDRESS         DEVICE  STATE"

static void
dump_arp(void)
{
	ulong	arp_tbl;		/* address of arp_tbl */
	ulong	*hash_buckets;
	ulong	hash;
	long	hash_bytes;
	int	nhash_buckets = 0;
	int	key_len;
	int	i;
	int	header_printed = 0;
	int	hash_mask = 0;
	ulong	nht;

	if (!symbol_exists("arp_tbl")) 
		error(FATAL, "arp_tbl does not exist in this kernel\n");

	arp_tbl = symbol_value("arp_tbl");

	/*
	 *  NOTE: 2.6.8 -> 2.6.9 neigh_table struct changed from:
	 *
	 *    struct neighbour *hash_buckets[32];
	 *  to
	 *    struct neighbour **hash_buckets;
	 *
	 *  Use 'hash_mask' as indicator to decide if we're dealing
	 *  with an array or a pointer.
	 *
	 * Around 2.6.37 neigh_hash_table struct has been introduced
	 * and pointer to it has been added to neigh_table.
	 */
	if (VALID_MEMBER(neigh_table_nht_ptr)) {
		readmem(arp_tbl + OFFSET(neigh_table_nht_ptr),
			KVADDR, &nht, sizeof(nht),
			"neigh_table nht", FAULT_ON_ERROR);
		/* NB! Re-use of offsets like neigh_table_hash_mask
		 * with neigh_hash_table structure */
		if (VALID_MEMBER(neigh_table_hash_mask)) {
			readmem(nht + OFFSET(neigh_table_hash_mask),
				KVADDR, &hash_mask, sizeof(hash_mask),
				"neigh_hash_table hash_mask", FAULT_ON_ERROR);

			nhash_buckets = hash_mask + 1;
		} else if (VALID_MEMBER(neigh_table_hash_shift)) {
			readmem(nht + OFFSET(neigh_table_hash_shift),
				KVADDR, &hash_mask, sizeof(hash_mask),
				"neigh_hash_table hash_shift", FAULT_ON_ERROR);

			nhash_buckets = 1U << hash_mask;
		}
	} else if (VALID_MEMBER(neigh_table_hash_mask)) {
		readmem(arp_tbl + OFFSET(neigh_table_hash_mask),
			KVADDR, &hash_mask, sizeof(hash_mask),
			"neigh_table hash_mask", FAULT_ON_ERROR);

		nhash_buckets = hash_mask + 1;
	} else
		nhash_buckets = (i = ARRAY_LENGTH(neigh_table_hash_buckets)) ?
			i : get_array_length("neigh_table.hash_buckets", 
				NULL, sizeof(void *));

	if (nhash_buckets == 0) {
		option_not_supported('a');
		return;
	}

	hash_bytes = nhash_buckets * sizeof(*hash_buckets);

	hash_buckets = (ulong *)GETBUF(hash_bytes);

	readmem(arp_tbl + OFFSET(neigh_table_key_len),
		KVADDR, &key_len, sizeof(key_len),
		"neigh_table key_len", FAULT_ON_ERROR);

	if (VALID_MEMBER(neigh_table_nht_ptr)) {
		readmem(nht + OFFSET(neigh_table_hash_buckets),
			KVADDR, &hash, sizeof(hash),
			"neigh_hash_table hash_buckets ptr", FAULT_ON_ERROR);

		readmem(hash, KVADDR, hash_buckets, hash_bytes,
			"neigh_hash_table hash_buckets", FAULT_ON_ERROR);
	} else if (hash_mask) {
		readmem(arp_tbl + OFFSET(neigh_table_hash_buckets), 
			KVADDR, &hash, sizeof(hash),
			"neigh_table hash_buckets pointer", FAULT_ON_ERROR);
		
		readmem(hash,
			KVADDR, hash_buckets, hash_bytes,
			"neigh_table hash_buckets", FAULT_ON_ERROR);
	} else
		readmem(arp_tbl + OFFSET(neigh_table_hash_buckets), 
			KVADDR, hash_buckets, hash_bytes,
			"neigh_table hash_buckets", FAULT_ON_ERROR);

	for (i = 0; i < nhash_buckets; i++) {
		if (hash_buckets[i] != (ulong)NULL) {
			if (!header_printed) {
				fprintf(fp, "%s\n", ARP_HEADING);
				header_printed = 1;
			}
			print_neighbour_q(hash_buckets[i], key_len);
		}
	}

	fflush(fp);

	FREEBUF(hash_buckets);
}

/*
 * Dump out the relevant information of a neighbour structure for the
 * ARP table.
 */
static void
print_neighbour_q(ulong addr, int key_len)
{
	int i;
	ulong	dev;			/* dev address of this struct */
	unsigned char *ha_buf;		/* buffer for hardware address */
	uint	ha_size;		/* size of HW address */
	uint	ipaddr;			/* hold ipaddr (aka primary_key) */
	struct devinfo dinfo;
	unsigned char state;		/* state of ARP entry */
	struct in_addr in_addr;

	ha_size = (i = ARRAY_LENGTH(neighbour_ha)) ?
		i : get_array_length("neighbour.ha", NULL, sizeof(char));
	ha_buf = (unsigned char *)GETBUF(ha_size);

	while (addr) {
		readmem(addr + OFFSET(neighbour_primary_key), KVADDR, 
			&ipaddr, sizeof(ipaddr), "neighbour primary_key", 
			FAULT_ON_ERROR);

		readmem(addr + OFFSET(neighbour_ha), KVADDR, ha_buf, ha_size,
			"neighbour ha", FAULT_ON_ERROR);

		readmem(addr + OFFSET(neighbour_dev), KVADDR, &dev, sizeof(dev),
			"neighbour dev", FAULT_ON_ERROR);
		get_netdev_info(dev, &dinfo);

		readmem(addr + OFFSET(neighbour_nud_state), KVADDR, 
			&state, sizeof(state), "neighbour nud_state", 
			FAULT_ON_ERROR);

		in_addr.s_addr = ipaddr;
		fprintf(fp, "%-16lx %-16s", addr, inet_ntoa(in_addr));

		switch (dinfo.dev_type) {
		case ARPHRD_ETHER:
			/*
			 * Use the actual HW address size in the device struct
			 * rather than the max size of the array (as was done
			 * during the readmem() call above....
			 */
			fprintf(fp, "%-10s ", "ETHER");
			dump_ether_hw(ha_buf, dinfo.dev_addr_len);
			break;
		case ARPHRD_NETROM:
			fprintf(fp, "%-10s ", "NETROM");
			dump_hw_addr(ha_buf, dinfo.dev_addr_len);
			break;
		case ARPHRD_EETHER:
			fprintf(fp, "%-10s ", "EETHER");
			dump_hw_addr(ha_buf, dinfo.dev_addr_len);
			break;
		case ARPHRD_AX25:
			fprintf(fp, "%-10s ", "AX25");
			dump_hw_addr(ha_buf, dinfo.dev_addr_len);
			break;
		case ARPHRD_PRONET:
			fprintf(fp, "%-10s ", "PRONET");
			dump_hw_addr(ha_buf, dinfo.dev_addr_len);
			break;
		case ARPHRD_CHAOS:
			fprintf(fp, "%-10s ", "CHAOS");
			dump_hw_addr(ha_buf, dinfo.dev_addr_len);
			break;
		case ARPHRD_IEEE802:
			fprintf(fp, "%-10s ", "IEEE802");
			dump_hw_addr(ha_buf, dinfo.dev_addr_len);	
			break;
		case ARPHRD_ARCNET:
			fprintf(fp, "%-10s ", "ARCNET");
			dump_hw_addr(ha_buf, dinfo.dev_addr_len);
			break;
		case ARPHRD_APPLETLK:
			fprintf(fp, "%-10s ", "APPLETLK");
			dump_hw_addr(ha_buf, dinfo.dev_addr_len);
			break;
		case ARPHRD_DLCI:
			fprintf(fp, "%-10s ", "DLCI");
			dump_hw_addr(ha_buf, dinfo.dev_addr_len);
			break;
		case ARPHRD_METRICOM:
			fprintf(fp, "%-10s ", "METRICOM");
			dump_hw_addr(ha_buf, dinfo.dev_addr_len);
			break;
		default:
			fprintf(fp, "%-10s ", "UNKNOWN");
			dump_hw_addr(ha_buf, dinfo.dev_addr_len);
			break;
		}

		fprintf(fp, " %-6s  ", dinfo.dev_name);

		arp_state_to_flags(state);

		readmem(addr + OFFSET(neighbour_next), KVADDR, 
			&addr, sizeof(addr), "neighbour next", FAULT_ON_ERROR);
	}

	FREEBUF(ha_buf);
}

/*
 * read netdevice info.... 
 */
static void
get_netdev_info(ulong devaddr, struct devinfo *dip)
{
	short	dev_type;

	get_device_name(devaddr, dip->dev_name);

	readmem(devaddr + net->dev_type, KVADDR, 
		&dev_type, sizeof(dev_type), net->dev_type_t, FAULT_ON_ERROR);

	dip->dev_type = dev_type;

	readmem(devaddr + net->dev_addr_len, KVADDR,
		&dip->dev_addr_len, sizeof(dip->dev_addr_len), net->dev_addr_t,
		FAULT_ON_ERROR);
}

/*
 *  Get the device name.
 */
static void
get_device_name(ulong devaddr, char *buf)
{
	ulong	name_addr;

	switch (net->flags & (STRUCT_DEVICE|STRUCT_NET_DEVICE))
	{
	case STRUCT_NET_DEVICE:
		if (net->net_device_name_index > 0) {
                	readmem(devaddr + net->dev_name, KVADDR,
                        	buf, net->net_device_name_index, 
				net->dev_name_t, FAULT_ON_ERROR);
			return;
		} 

		/* fallthrough */

        case STRUCT_DEVICE:
                readmem(devaddr + net->dev_name, KVADDR,
                        &name_addr, sizeof(name_addr), net->dev_name_t,
                        FAULT_ON_ERROR);
                read_string(name_addr, buf, DEV_NAME_MAX);
                break;
	}
}

/*
 *  Get the device address.
 *
 *  {net_}device->ip_ptr points to in_device.
 *  in_device->in_ifaddr points to in_ifaddr list.
 *  in_ifaddr->ifa_address contains the address. 
 *  in_ifaddr->ifa_next points to the next in_ifaddr in the list (if any).
 * 
 */
static long
get_device_address(ulong devaddr, char **bufp, long buflen)
{
	ulong ip_ptr, ifa_list;
	struct in_addr ifa_address;
	char *buf;
	char buf2[BUFSIZE];
	long pos = 0;

	buf = *bufp;
	BZERO(buf, buflen);
	BZERO(buf2, BUFSIZE);

        readmem(devaddr + net->dev_ip_ptr, KVADDR,
        	&ip_ptr, sizeof(ulong), "ip_ptr", FAULT_ON_ERROR);

	if (!ip_ptr)
		return buflen;

        readmem(ip_ptr + OFFSET(in_device_ifa_list), KVADDR,
        	&ifa_list, sizeof(ulong), "ifa_list", FAULT_ON_ERROR);

	while (ifa_list) {
        	readmem(ifa_list + OFFSET(in_ifaddr_ifa_address), KVADDR,
        		&ifa_address, sizeof(struct in_addr), "ifa_address", 
			FAULT_ON_ERROR);

		sprintf(buf2, "%s%s", pos ? ", " : "", inet_ntoa(ifa_address));
		if (pos + strlen(buf2) >= buflen) {
			RESIZEBUF(*bufp, buflen, buflen * 2);
			buf = *bufp;
			BZERO(buf + buflen, buflen);
			buflen *= 2;
		}
		BCOPY(buf2, &buf[pos], strlen(buf2));
		pos += strlen(buf2);

        	readmem(ifa_list + OFFSET(in_ifaddr_ifa_next), KVADDR,
        		&ifa_list, sizeof(ulong), "ifa_next", FAULT_ON_ERROR);
	}
	return buflen;
}

static void
get_device_ip6_address(ulong devaddr, char **bufp, long buflen)
{
	ulong ip6_ptr = 0, pos = 0, bufsize = buflen, addr = 0;
	struct in6_addr ip6_addr;
	char *buf;
	char str[INET6_ADDRSTRLEN] = {0};
	char buffer[INET6_ADDRSTRLEN + 2] = {0};
	uint len = 0;

	buf = *bufp;
	pos = strlen(buf);

	readmem(devaddr + OFFSET(net_device_ip6_ptr), KVADDR,
		&ip6_ptr, sizeof(ulong), "ip6_ptr", FAULT_ON_ERROR);

	if (!ip6_ptr)
		return;

	/*
	 * 502a2ffd7376 ("ipv6: convert idev_list to list macros")
	 * v2.6.35-rc1~473^2~733
	 */
	if (VALID_MEMBER(inet6_ifaddr_if_list)) {
		struct list_data list_data, *ld;
		ulong cnt = 0, i;

		ld = &list_data;
		BZERO(ld, sizeof(struct list_data));
		ld->flags |= LIST_ALLOCATE;
		ld->start = ip6_ptr + OFFSET(inet6_dev_addr_list);
		ld->list_head_offset = OFFSET(inet6_ifaddr_if_list);
		cnt = do_list(ld);

		for (i = 1; i < cnt; i++) {

			addr = ld->list_ptr[i] + OFFSET(inet6_ifaddr_addr);
			readmem(addr + OFFSET(in6_addr_in6_u), KVADDR, &ip6_addr,
				sizeof(struct in6_addr), "in6_addr.in6_u", FAULT_ON_ERROR);

			inet_ntop(AF_INET6, (void*)&ip6_addr, str, INET6_ADDRSTRLEN);
			sprintf(buffer, "%s%s", pos ? ", " : "", str);
			len = strlen(buffer);
			if (pos + len >= bufsize) {
				RESIZEBUF(*bufp, bufsize, bufsize + buflen);
				buf = *bufp;
				BZERO(buf + bufsize, buflen);
				bufsize += buflen;
			}
			BCOPY(buffer, &buf[pos], len);
			pos += len;
		}

		FREEBUF(ld->list_ptr);
		return;
	}

	if (INVALID_MEMBER(inet6_ifaddr_if_next))
		return;

	readmem(ip6_ptr + OFFSET(inet6_dev_addr_list), KVADDR,
		&addr, sizeof(void *), "inet6_dev.addr_list", FAULT_ON_ERROR);

	while (addr) {
		readmem(addr + OFFSET(in6_addr_in6_u), KVADDR, &ip6_addr,
			sizeof(struct in6_addr), "in6_addr.in6_u", FAULT_ON_ERROR);
		inet_ntop(AF_INET6, (void*)&ip6_addr, str, INET6_ADDRSTRLEN);
		sprintf(buffer, "%s%s", pos ? ", " : "", str);
		len = strlen(buffer);

		if (pos + len >= bufsize) {
			RESIZEBUF(*bufp, bufsize, bufsize + buflen);
			buf = *bufp;
			BZERO(buf + bufsize, buflen);
			bufsize += buflen;
		}
		BCOPY(buffer, &buf[pos], len);
		pos += len;
		readmem(addr + OFFSET(inet6_ifaddr_if_next), KVADDR, &addr,
			sizeof(void *), "inet6_ifaddr.if_next", FAULT_ON_ERROR);
	}
}

/*
 *  Get the family, type, local and destination address/port pairs.
 */
static void
get_sock_info(ulong sock, char *buf)
{
	uint32_t daddr, rcv_saddr;
	uint16_t dport, sport;
	ushort family, type;
	ushort num ATTRIBUTE_UNUSED;
	char *sockbuf, *inet_sockbuf;
	ulong ipv6_pinfo, ipv6_rcv_saddr, ipv6_daddr;
	uint16_t u6_addr16_src[8];
	uint16_t u6_addr16_dest[8];
	char buf2[BUFSIZE];
	struct in_addr in_addr;
	int len;

	BZERO(buf, BUFSIZE);
	BZERO(buf2, BUFSIZE);
	sockbuf = inet_sockbuf = NULL;
	rcv_saddr = daddr = 0;
	dport = sport = 0;
	family = type = 0;
	ipv6_pinfo = 0;

	switch (net->flags & (SOCK_V1|SOCK_V2))
	{
	case SOCK_V1:
		sockbuf = GETBUF(SIZE(sock));
	        readmem(sock, KVADDR, sockbuf, SIZE(sock), 
			"sock buffer", FAULT_ON_ERROR);
	
		daddr = UINT(sockbuf + OFFSET(sock_daddr));
		rcv_saddr = UINT(sockbuf + OFFSET(sock_rcv_saddr));
		dport = USHORT(sockbuf + OFFSET(sock_dport));
		sport = USHORT(sockbuf + OFFSET(sock_sport));
		num = USHORT(sockbuf + OFFSET(sock_num));
		family = USHORT(sockbuf + OFFSET(sock_family));
		type = USHORT(sockbuf + OFFSET(sock_type));
		break;

	case SOCK_V2:
		inet_sockbuf = GETBUF(SIZE(inet_sock));
	        readmem(sock, KVADDR, inet_sockbuf, SIZE(inet_sock), 
			"inet_sock buffer", FAULT_ON_ERROR);

		daddr = UINT(inet_sockbuf + OFFSET(inet_sock_inet) +
			OFFSET(inet_opt_daddr));
		rcv_saddr = UINT(inet_sockbuf + OFFSET(inet_sock_inet) +
			OFFSET(inet_opt_rcv_saddr));
		dport = USHORT(inet_sockbuf + OFFSET(inet_sock_inet) +
			OFFSET(inet_opt_dport));
		sport = USHORT(inet_sockbuf + OFFSET(inet_sock_inet) +
			OFFSET(inet_opt_sport));
		num = USHORT(inet_sockbuf + OFFSET(inet_sock_inet) +
			OFFSET(inet_opt_num));
		family = USHORT(inet_sockbuf + OFFSET(sock_common_skc_family));
		type = USHORT(inet_sockbuf + OFFSET(sock_sk_type));
		ipv6_pinfo = ULONG(inet_sockbuf + SIZE(sock));
		break;
	}

	switch (family)
	{
	case AF_UNSPEC:
		sprintf(buf, "UNSPEC:"); break;
	case AF_UNIX: 
		sprintf(buf, "UNIX:"); break;
	case AF_INET: 
		sprintf(buf, "INET:"); break;
	case AF_AX25: 
		sprintf(buf, "AX25:"); break;
	case AF_IPX:  
		sprintf(buf, "IPX:"); break;
	case AF_APPLETALK:
		sprintf(buf, "APPLETALK:"); break;
	case AF_NETROM:
		sprintf(buf, "NETROM:"); break;
	case AF_BRIDGE:
		sprintf(buf, "BRIDGE:"); break;
	case AF_ATMPVC:
		sprintf(buf, "ATMPVC:"); break;
	case AF_X25:  
		sprintf(buf, "X25:"); break;
	case AF_INET6:
		sprintf(buf, "INET6:"); break;
	case AF_ROSE: 
		sprintf(buf, "ROSE:"); break;
	case AF_DECnet:
		sprintf(buf, "DECnet:"); break;
	case AF_NETBEUI:
		sprintf(buf, "NETBEUI:"); break;
	case AF_SECURITY: 
		sprintf(buf, "SECURITY/KEY:"); break;
	case AF_NETLINK: 
		sprintf(buf, "NETLINK/ROUTE:"); break;
	case AF_PACKET:  
		sprintf(buf, "PACKET:"); break;
	case AF_ASH:     
		sprintf(buf, "ASH:"); break;
	case AF_ECONET:  
		sprintf(buf, "ECONET:"); break;
	case AF_ATMSVC: 
		sprintf(buf, "ATMSVC:"); break;
	case AF_SNA:    
		sprintf(buf, "SNA:"); break;
	case AF_IRDA:   
		sprintf(buf, "IRDA:"); break;
#ifndef AF_PPPOX
#define AF_PPPOX 24
#endif
	case AF_PPPOX:  
		sprintf(buf, "PPPOX:"); break;
	default:
		sprintf(buf, "%d:", family); break;
	}

	switch (type)
	{
	case SOCK_STREAM:
		sprintf(&buf[strlen(buf)], "STREAM"); break;
	case SOCK_DGRAM:
		sprintf(&buf[strlen(buf)], "DGRAM "); break;
	case SOCK_RAW:
		sprintf(&buf[strlen(buf)], "RAW"); break;
	case SOCK_RDM: 
		sprintf(&buf[strlen(buf)], "RDM"); break;
	case SOCK_SEQPACKET:
		sprintf(&buf[strlen(buf)], "SEQPACKET"); break;
	case SOCK_PACKET:
		sprintf(&buf[strlen(buf)], "PACKET"); break;
	default:
		sprintf(&buf[strlen(buf)], "%d", type); break;
	}

	/* make sure we have room at the end... */
//	sprintf(&buf[strlen(buf)], "%s", space(MINSPACE-1));
	sprintf(&buf[strlen(buf)], " ");
           
	if (family == AF_INET) {
		if (BITS32()) {
			in_addr.s_addr = rcv_saddr;
			sprintf(&buf[strlen(buf)], "%*s-%-*d%s",
				BYTES_IP_ADDR,
				inet_ntoa(in_addr),
				BYTES_PORT_NUM,
				ntohs(sport),
				space(1));
			in_addr.s_addr = daddr;
			sprintf(&buf[strlen(buf)], "%*s-%-*d%s",
				BYTES_IP_ADDR,
				inet_ntoa(in_addr), 
				BYTES_PORT_NUM,
				ntohs(dport),
				space(1));
		} else {
			in_addr.s_addr = rcv_saddr;
	                sprintf(&buf[strlen(buf)], " %s-%d ",
	                        inet_ntoa(in_addr),
	                        ntohs(sport));
			in_addr.s_addr = daddr;
	                sprintf(&buf[strlen(buf)], "%s-%d",
	                        inet_ntoa(in_addr),
	                        ntohs(dport));
		}
	}

	if (sockbuf)
		FREEBUF(sockbuf);
	if (inet_sockbuf)
		FREEBUF(inet_sockbuf);

	if (family != AF_INET6)
		return;

	switch (net->flags & (SOCK_V1|SOCK_V2))
	{
	case SOCK_V1:
		break;

	case SOCK_V2:
		if (VALID_MEMBER(ipv6_pinfo_rcv_saddr) &&
		    VALID_MEMBER(ipv6_pinfo_daddr)) {
			ipv6_rcv_saddr = ipv6_pinfo + OFFSET(ipv6_pinfo_rcv_saddr);
			ipv6_daddr = ipv6_pinfo + OFFSET(ipv6_pinfo_daddr);
		} else if (VALID_MEMBER(sock_sk_common) &&
			   VALID_MEMBER(sock_common_skc_v6_daddr) &&
			   VALID_MEMBER(sock_common_skc_v6_rcv_saddr)) {
			ipv6_rcv_saddr = sock + OFFSET(sock_sk_common) + OFFSET(sock_common_skc_v6_rcv_saddr);
			ipv6_daddr = sock + OFFSET(sock_sk_common) + OFFSET(sock_common_skc_v6_daddr);
		} else {
			sprintf(&buf[strlen(buf)], "%s", "(cannot get IPv6 addresses)");
			break;
		}

		if (!readmem(ipv6_rcv_saddr, KVADDR, u6_addr16_src, SIZE(in6_addr),
                    "ipv6_rcv_saddr buffer", QUIET|RETURN_ON_ERROR))
			break;
                if (!readmem(ipv6_daddr, KVADDR, u6_addr16_dest, SIZE(in6_addr),
                    "ipv6_daddr buffer", QUIET|RETURN_ON_ERROR))
			break;

		sprintf(&buf[strlen(buf)], "%*s ", BITS32() ? 22 : 12,
			dump_in6_addr_port(u6_addr16_src, sport, buf2, &len));
		if (BITS32() && (len > 22))
			len = 1;
		mkstring(dump_in6_addr_port(u6_addr16_dest, dport, buf2, NULL),
			len, CENTER, NULL);
		sprintf(&buf[strlen(buf)], "%s", buf2);

		break;
	}
}

static char *
dump_in6_addr_port(uint16_t *addr, uint16_t port, char *buf, int *len)
{
	sprintf(buf, "%x:%x:%x:%x:%x:%x:%x:%x-%d",
                ntohs(addr[0]),
                ntohs(addr[1]),
                ntohs(addr[2]),
                ntohs(addr[3]),
                ntohs(addr[4]),
                ntohs(addr[5]),
                ntohs(addr[6]),
                ntohs(addr[7]),
                ntohs(port));

	if (len)
		*len = strlen(buf);

	return buf;
}


/*
 *	XXX - copied from neighbour.h !!!!!!
 *
 *      Neighbor Cache Entry States.
 */
#define NUD_INCOMPLETE  0x01
#define NUD_REACHABLE   0x02
#define NUD_STALE       0x04
#define NUD_DELAY       0x08
#define NUD_PROBE       0x10
#define NUD_FAILED      0x20
#define NUD_NOARP       0x40
#define NUD_PERMANENT   0x80

#define FLAGBUF_SIZE 100

#define FILLBUF(s)							\
do {									\
	char *bp;							\
	int blen;							\
	blen=strlen(flag_buffer);					\
	if ((blen + strlen(s)) < FLAGBUF_SIZE-2) {			\
		bp = &flag_buffer[blen];				\
		if (blen != 0) {					\
			sprintf(bp, "|%s", (s));			\
		} else {						\
			sprintf(bp, "%s", (s));				\
		}							\
	}								\
} while(0)

/*
 * Take the state of the ARP entry and print it out the flag associated
 * with the binary state...
 */
static void
arp_state_to_flags(unsigned char state)
{
	char flag_buffer[FLAGBUF_SIZE];
	int had_flags = 0;

	if (!state) { 
		fprintf(fp, "\n");
		return;
	}

	bzero(flag_buffer, FLAGBUF_SIZE);

	if (state & NUD_INCOMPLETE) {
		FILLBUF("INCOMPLETE");
		had_flags = 1;
	}

	if (state & NUD_REACHABLE) {
		FILLBUF("REACHABLE");
		had_flags = 1;
	}

	if (state & NUD_STALE) {
		FILLBUF("STALE");
		had_flags = 1;
	}

	if (state & NUD_DELAY) {
		FILLBUF("DELAY");
		had_flags = 1;
	}

	if (state & NUD_PROBE) {
		FILLBUF("PROBE");
		had_flags = 1;
	}

	if (state & NUD_FAILED) {
		FILLBUF("FAILED");
		had_flags = 1;
	}

	if (state & NUD_NOARP) {
		FILLBUF("NOARP");
		had_flags = 1;
	}

	if (state & NUD_PERMANENT) {
		FILLBUF("PERMANENT");
		had_flags = 1;
	}

	if (had_flags) {
		fprintf(fp, "%s\n", flag_buffer);
		/* fprintf(fp, "%29.29s%s)\n", " ",  flag_buffer); */
	}
}

#undef FILLBUF

/*
 * Print out a formatted ethernet HW address....
 */
static void
dump_ether_hw(unsigned char *ha, int len)
{
	int i;

	for (i = 0; i < len; i++) {
		char sep = ':';
		if (i == (len - 1)) {
			sep = ' ';
		}
		fprintf(fp, "%02x%c", ha[i], sep);
	}
}

/*
 * Catchall routine for dumping out a HA address whose format we
 * don't know about...
 */
static void
dump_hw_addr(unsigned char *ha, int len)
{
	int i;

	for (i = 0; i < len; i++) {
		fprintf(fp, "%02x ", ha[i]);
	}
}

/*
 *  help -N output
 */
void
dump_net_table(void)
{
	int others;

	others = 0;
	fprintf(fp, "              flags: %lx (", net->flags);
	if (net->flags & NETDEV_INIT)
		fprintf(fp, "%sNETDEV_INIT", others++ ? "|" : "");
	if (net->flags & STRUCT_DEVICE)
		fprintf(fp, "%sSTRUCT_DEVICE", others++ ? "|" : "");
	if (net->flags & STRUCT_NET_DEVICE)
		fprintf(fp, "%sSTRUCT_NET_DEVICE", others++ ? "|" : "");
	if (net->flags & NO_INET_SOCK)
		fprintf(fp, "%sNO_INET_SOCK", others++ ? "|" : "");
	if (net->flags & SOCK_V1)
		fprintf(fp, "%sSOCK_V1", others++ ? "|" : "");
	if (net->flags & SOCK_V2)
		fprintf(fp, "%sSOCK_V2", others++ ? "|" : "");
	fprintf(fp, ")\n");

	fprintf(fp, "            netdevice: \"%s\"\n", net->netdevice); 
	fprintf(fp, "           dev_name_t: \"%s\"\n", net->dev_name_t);
	fprintf(fp, "           dev_type_t: \"%s\"\n", net->dev_type_t);
	fprintf(fp, "           dev_addr_t: \"%s\"\n", net->dev_addr_t);
        fprintf(fp, "             dev_name: %ld\n", net->dev_name);
	fprintf(fp, "             dev_next: %ld\n", net->dev_next);
        fprintf(fp, "             dev_type: %ld\n", net->dev_type);
        fprintf(fp, "           dev_ip_ptr: %ld\n", net->dev_ip_ptr);
        fprintf(fp, "         dev_addr_len: %ld\n", net->dev_addr_len);
	fprintf(fp, "net_device_name_index: %d\n", net->net_device_name_index);
}


/*
 * Dump the open sockets for a given PID.
 */
static void
dump_sockets(ulong flag, struct reference *ref)
{
    	struct task_context *tc;
    	ulong value;
    	int subsequent;

    	if (!args[optind]) { 
		if (!NET_REFERENCE_CHECK(ref))
            		print_task_header(fp, CURRENT_CONTEXT(), 0);
        	dump_sockets_workhorse(CURRENT_TASK(), flag, ref);
        	return;
    	}

	subsequent = 0;

	while (args[optind]) {

                switch (str_to_context(args[optind], &value, &tc))
                {
                case STR_PID:
                        for (tc = pid_to_context(value); tc; tc = tc->tc_next) {
                                if (!NET_REFERENCE_CHECK(ref))
                                        print_task_header(fp, tc, subsequent++);
                                dump_sockets_workhorse(tc->task, flag, ref);
                        }
                        break;

                case STR_TASK:
                        if (!NET_REFERENCE_CHECK(ref))
                                print_task_header(fp, tc, subsequent++);
                        dump_sockets_workhorse(tc->task, flag, ref);
                        break;

                case STR_INVALID:
                        error(INFO, "%sinvalid task or pid value: %s\n",
				subsequent++ ? "\n" : "", args[optind]);
                        break;
                }

		optind++;
	}
}

/*
 *  Find all sockets in the designated task and call sym_socket_dump()
 *  to display them.
 */
void
dump_sockets_workhorse(ulong task, ulong flag, struct reference *ref)
{
	ulong files_struct_addr = 0, fdtable_addr = 0;
	int max_fdset = 0;
	int max_fds = 0;
	ulong open_fds_addr = 0;
	ulong *open_fds;
	int open_fds_size;
	ulong fd;
	ulong file;
	int i, j;
	int sockets_found = 0;
	ulong value;

       /* 
        * Steps to getting open sockets:
        *
        * 1)  task->files (struct files_struct)
        * 2)  files->fd   (struct file **)
        * 3)  cycle through from 0 to files->open_fds offset from *fd
        *     i.e.    fd[0], fd[1], fd[2]  are pointers to the first three
        *     open file descriptors.  Thus, we have:
        *         struct file *fd[0], *fd[1], *fd[2],...
        *
        * 4) file->f_dentry (struct dentry)
        * 5) dentry->d_inode (struct inode)
        * 6) S_ISSOCK(inode.mode)
        *      Assuming it _is_ a socket:
        * 7) inode.u (struct socket)   -- offset 0xdc from inode pointer
        */

	readmem(task + OFFSET(task_struct_files), KVADDR, &files_struct_addr,
            sizeof(void *), "task files contents", FAULT_ON_ERROR);

        if (files_struct_addr) {
                if (VALID_MEMBER(files_struct_max_fdset)) {
		 	readmem(files_struct_addr + OFFSET(files_struct_max_fdset),
		          	KVADDR, &max_fdset, sizeof(int),
				"files_struct max_fdset", FAULT_ON_ERROR);
		      	readmem(files_struct_addr + OFFSET(files_struct_max_fds),
        	        	KVADDR, &max_fds, sizeof(int), "files_struct max_fds",
                	   	FAULT_ON_ERROR);
                }
		else if (VALID_MEMBER(files_struct_fdt)) {
			readmem(files_struct_addr + OFFSET(files_struct_fdt), KVADDR,
				&fdtable_addr, sizeof(void *), "fdtable buffer",
				FAULT_ON_ERROR);
			if (VALID_MEMBER(fdtable_max_fdset))
		      		readmem(fdtable_addr + OFFSET(fdtable_max_fdset),
        	         		KVADDR, &max_fdset, sizeof(int),
					"fdtable_struct max_fdset", FAULT_ON_ERROR);
			else
				max_fdset = -1;
		      	readmem(fdtable_addr + OFFSET(fdtable_max_fds),
	      	            	KVADDR, &max_fds, sizeof(int), "fdtable_struct max_fds",
	               	    	FAULT_ON_ERROR);
    		}
	}

	if ((VALID_MEMBER(files_struct_fdt) && !fdtable_addr) ||
	    !files_struct_addr || (max_fdset == 0) || (max_fds == 0)) {
		if (!NET_REFERENCE_CHECK(ref))
			fprintf(fp, "No open sockets.\n");
		return;
	}

	if (VALID_MEMBER(fdtable_open_fds)){
		readmem(fdtable_addr + OFFSET(fdtable_open_fds), KVADDR,
     	  		&open_fds_addr, sizeof(void *), "files_struct open_fds addr",
	            	FAULT_ON_ERROR);
		readmem(fdtable_addr + OFFSET(fdtable_fd), KVADDR, &fd,
           		sizeof(void *), "files_struct fd addr", FAULT_ON_ERROR);
	} else {
		readmem(files_struct_addr + OFFSET(files_struct_open_fds), KVADDR,
            		&open_fds_addr, sizeof(void *), "files_struct open_fds addr",
	          	FAULT_ON_ERROR);
		readmem(files_struct_addr + OFFSET(files_struct_fd), KVADDR, &fd,
            		sizeof(void *), "files_struct fd addr", FAULT_ON_ERROR);
	}

	open_fds_size = MAX(max_fdset, max_fds) / BITS_PER_BYTE;
	open_fds = (ulong *)GETBUF(open_fds_size);
	if (!open_fds)
		return;

	if (open_fds_addr) 
		readmem(open_fds_addr, KVADDR, open_fds, open_fds_size,
	               	"files_struct open_fds", FAULT_ON_ERROR);
    	if (!open_fds_addr || !fd) { 
		if (!NET_REFERENCE_CHECK(ref))
			fprintf(fp, "No open sockets.\n");
		FREEBUF(open_fds);
        	return;
	}

	if (NET_REFERENCE_CHECK(ref)) {
                if (IS_A_NUMBER(ref->str)) {
	                if (hexadecimal_only(ref->str, 0)) {
	                        ref->hexval = htol(ref->str,
	                        	FAULT_ON_ERROR, NULL);
	                        ref->cmdflags |= NET_REF_HEXNUM;
	                } else {
	                        value = dtol(ref->str, FAULT_ON_ERROR, NULL);
	                        if (value <= MAX(max_fdset, max_fds)) {
	                                ref->decval = value;
	                                ref->cmdflags |= NET_REF_DECNUM;
	                        } else {
	                                ref->hexval = htol(ref->str,
						FAULT_ON_ERROR, NULL);
	                                ref->cmdflags |= NET_REF_HEXNUM;
	                        }
	                }
                }
		ref->ref1 = task;
	}

    	j = 0;
    	for (;;) {
	        unsigned long set;
	        i = j * BITS_PER_LONG;
	        if (((max_fdset >= 0) && (i >= max_fdset)) || (i >= max_fds))
	            	break;
	        set = open_fds[j++];
	        while (set) {
	            	if (set & 1) {
		                readmem(fd + i*sizeof(struct file *), KVADDR, 
		                        &file, sizeof(struct file *), 
		                        "fd file", FAULT_ON_ERROR);
		                if (file) {
		                    	if (sym_socket_dump(file, i, 
					    sockets_found, flag, ref)) {
		                        	sockets_found++;
					}
		                }
	            	}
	            	i++;
	            	set >>= 1;
	        }
        }

    	if (!sockets_found && !NET_REFERENCE_CHECK(ref))
        	fprintf(fp, "No open sockets.\n");

	if (NET_REFERENCE_FOUND(ref))
		fprintf(fp, "\n");

	FREEBUF(open_fds);
}


/*
 *  Dump a struct socket symbolically.  Dave makes this _very_ easy.
 *
 *  Return TRUE if we found a socket, FALSE otherwise.
 */

static char *socket_hdr_32 = 
"FD   SOCKET     SOCK    FAMILY:TYPE          SOURCE-PORT      DESTINATION-PORT";
static char *socket_hdr_64 = 
"FD      SOCKET            SOCK       FAMILY:TYPE SOURCE-PORT DESTINATION-PORT";

static int
sym_socket_dump(ulong file, 
		int fd, 
		int sockets_found, 
		ulong flag,
		struct reference *ref)
{
	uint16_t umode16 = 0;
	uint32_t umode32 = 0;
    	uint mode = 0;
    	ulong dentry = 0, inode = 0,
        struct_socket = 0;
	ulong sock = 0;
	char *file_buf, *dentry_buf, *inode_buf, *socket_buf;
	char buf1[BUFSIZE];
	char buf2[BUFSIZE];
	char *socket_hdr = BITS32() ? socket_hdr_32 : socket_hdr_64;
	unsigned int radix;

	file_buf = fill_file_cache(file);
	dentry = ULONG(file_buf + OFFSET(file_f_dentry));

	if (flag & d_FLAG)
		radix = 10;
	else if (flag & x_FLAG)
		radix = 16;
	else
		radix = 0;

    	if (!dentry)
        	return FALSE;

	dentry_buf = fill_dentry_cache(dentry);
	inode = ULONG(dentry_buf + OFFSET(dentry_d_inode));

    	if (!inode)
        	return FALSE; 

	inode_buf = fill_inode_cache(inode);


	switch (SIZE(umode_t))
	{
	case SIZEOF_32BIT:
		umode32 = UINT(inode_buf + OFFSET(inode_i_mode));
		break;

	case SIZEOF_16BIT:
		umode16 = USHORT(inode_buf + OFFSET(inode_i_mode));
		break;
	}

	if (SIZE(umode_t) == SIZEOF_32BIT)
		mode = umode32;
	else
		mode = (uint)umode16;

    	if (!S_ISSOCK(mode))
        	return FALSE;

	/* 
	 * 2.6 (SOCK_V2) -- socket is inode addr minus sizeof(struct socket) 
	 */
	switch (net->flags & (SOCK_V1|SOCK_V2))  
	{
	case SOCK_V1:
    		struct_socket = inode + OFFSET(inode_u);
		sock = ULONG(inode_buf + OFFSET(inode_u) + OFFSET(socket_sk));
		break;

	case SOCK_V2:
		if (!VALID_SIZE(inet_sock)) 
			error(FATAL, 
              	           "cannot determine what an inet_sock structure is\n");
    		struct_socket = inode - OFFSET(socket_alloc_vfs_inode);
		socket_buf = GETBUF(SIZE(socket));
                readmem(struct_socket, KVADDR, socket_buf,
                        SIZE(socket), "socket buffer", FAULT_ON_ERROR);
		sock = ULONG(socket_buf + OFFSET(socket_sk));
		FREEBUF(socket_buf);
		break;
	} 

	if (NET_REFERENCE_CHECK(ref)) {
		if ((ref->cmdflags & NET_REF_HEXNUM) &&
		    ((ref->hexval == sock) || (ref->hexval == struct_socket)))
			ref->cmdflags |= NET_REF_FOUND_ITEM;
		else if ((ref->cmdflags & NET_REF_DECNUM) &&
			(ref->decval == (ulong)fd))
			ref->cmdflags |= NET_REF_FOUND_ITEM;
                else if ((ref->cmdflags & NET_REF_HEXNUM) &&
                        (ref->hexval == (ulong)fd))
                        ref->cmdflags |= NET_REF_FOUND_ITEM;

		if (!(ref->cmdflags & NET_REF_FOUND_ITEM))
			return FALSE;

		ref->cmdflags &= ~NET_REF_FOUND_ITEM;
		ref->cmdflags |= NET_REF_FOUND;

		if (!(ref->cmdflags & NET_TASK_HEADER_PRINTED)) {
			print_task_header(fp, task_to_context(ref->ref1), 0);
			ref->cmdflags |= NET_TASK_HEADER_PRINTED;
		}

		if (!(ref->cmdflags & NET_SOCK_HEADER_PRINTED)) {
			sockets_found = 0;
			ref->cmdflags |= NET_SOCK_HEADER_PRINTED;
		}
	}

	switch (flag & (S_FLAG|s_FLAG))
	{
	case S_FLAG:
		fprintf(fp, "%sFD  %s  %s\n", sockets_found ? "\n" : "",
			mkstring(buf1, VADDR_PRLEN, CENTER|LJUST, "SOCKET"),
			mkstring(buf2, VADDR_PRLEN, CENTER|LJUST, "SOCK"));
		fprintf(fp, "%2d  %s  %s\n\n",
			fd, 
			mkstring(buf1, VADDR_PRLEN, RJUST|LONG_HEX, 
			MKSTR(struct_socket)),
			mkstring(buf2, VADDR_PRLEN, RJUST|LONG_HEX, 
			MKSTR(sock)));

    		dump_struct("socket", struct_socket, radix);
		switch (net->flags & (SOCK_V1|SOCK_V2))  
		{
		case SOCK_V1:
    			dump_struct("sock", sock, radix);
			break;
		case SOCK_V2:
			if (STRUCT_EXISTS("inet_sock") && !(net->flags & NO_INET_SOCK))
				dump_struct("inet_sock", sock, radix);
			else if (STRUCT_EXISTS("sock"))
				dump_struct("sock", sock, radix);
			else
				fprintf(fp, "\nunable to display inet_sock structure\n");
			break;
		}
		break;

	case s_FLAG:
		if (!sockets_found) {
			fprintf(fp, "%s\n", socket_hdr);
		}
		fprintf(fp, "%2d%s%s%s%s%s",
			fd, space(MINSPACE), 
			mkstring(buf1, VADDR_PRLEN, RJUST|LONG_HEX, 
			MKSTR(struct_socket)),
			space(MINSPACE),
			mkstring(buf2, VADDR_PRLEN, RJUST|LONG_HEX,
                        MKSTR(sock)),
		        space(MINSPACE)); 

		buf1[0] = NULLCHAR;
		get_sock_info(sock, buf1);
		fprintf(fp, "%s\n", buf1);

		return TRUE;

	default:
		error(FATAL, "illegal flag: %lx\n", flag);
	}

    	return TRUE;
}

/* cmi@nvidia.com */
static ulong
read_pointer1(ulong addr)
{
        ulong buf[1];

        readmem(addr, KVADDR, buf, sizeof(ulong), "addr", FAULT_ON_ERROR);

        return buf[0];
}

static ulong
read_pointer2(ulong addr, char *type, char *member)
{
        int offset;
        char *buf;
        ulong val;

        offset = MEMBER_OFFSET(type, member);
        buf = malloc(offset+sizeof(ulong));

        if (buf == NULL)
                return 0;

        readmem(addr, KVADDR, buf, offset + sizeof(ulong), "addr", FAULT_ON_ERROR);

        val =  *((ulong *)&buf[offset]);
        free(buf);

        return val;
}

static int
read_int(ulong addr, char *type, char *member)
{
        int offset;
        char *buf;
        int val;

        offset = MEMBER_OFFSET(type, member);
        buf = malloc(offset+sizeof(ulong));

        if (buf == NULL)
                return 0;

        readmem(addr, KVADDR, buf, offset + sizeof(int), "addr", FAULT_ON_ERROR);

        val =  *((int *)&buf[offset]);
        free(buf);

        return val;
}

static unsigned int
read_u32(ulong addr, char *type, char *member)
{
        int offset;
        char *buf;
        unsigned int val;

        offset = MEMBER_OFFSET(type, member);
        buf = malloc(offset+sizeof(ulong));

        if (buf == NULL)
                return 0;

        readmem(addr, KVADDR, buf, offset + sizeof(unsigned int), "addr", FAULT_ON_ERROR);

        val =  *((int *)&buf[offset]);
        free(buf);

        return val;
}

static unsigned short
read_u16(ulong addr, char *type, char *member)
{
        int offset;
        char *buf;
        unsigned short val;

        offset = MEMBER_OFFSET(type, member);
        buf = malloc(offset+sizeof(ulong));

        if (buf == NULL)
                return 0;

        readmem(addr, KVADDR, buf, offset + sizeof(unsigned short), "addr", FAULT_ON_ERROR);

        val =  *((int *)&buf[offset]);
        free(buf);

        return val;
}

static char
read_char(ulong addr)
{
        char buf[1];
        char val;

        if (buf == NULL)
                return 0;

        readmem(addr, KVADDR, buf, 1, "addr", FAULT_ON_ERROR);

        val =  *((char *)&buf[0]);

        return val;
}

void
cmd_table(void)
{
	int c;
	char *addr = NULL;
	char *ptr;
	ulong a = 0;
	struct list_data group, *ld_group;
	struct list_data fte, *ld_fte;
	struct list_data rule, *ld_rule;
	int n1, n2, n3, i1, i2, i3;
	int show = 1;
	int no_fte = 0;
	int dest = 0;

	while ((c = getopt(argcnt, args, "bcd")) != EOF) {
		switch (c) {
		case 'b':
			show = 2;
		case 'c':
			no_fte = 1;
			addr = optarg;
			break;
		case 'd':
			dest = 1;
			break;
		default:
			return;
		}
	}

	addr = args[optind];
	if (addr == NULL) {
		fprintf(fp, "addr is null\n");
		return;
	}

	a = strtoul(addr, &ptr, 16);

	if (!dest) {
		fprintf(fp, "mlx5_flow_table  %lx -x\n", a);
	}

	ld_group =  &group;
	BZERO(ld_group, sizeof(struct list_data));
	ld_group->flags |= LIST_ALLOCATE;

	ld_group->start = ld_group->end = a + MEMBER_OFFSET("fs_node", "children");
	ld_group->list_head_offset = 0;

	n1 = do_list(ld_group);

	if (show == 1) {
		for (i1 = 1; i1 < n1; ++i1) {
			ulong t1 = ld_group->list_ptr[i1];
			if (!dest) {
				fprintf(fp, "\tmlx5_flow_group.mask %lx -x\n", t1);
			}

			ld_fte =  &fte;
			BZERO(ld_fte, sizeof(struct list_data));
			ld_fte->flags |= LIST_ALLOCATE;

			ld_fte->start = ld_fte->end = t1 + MEMBER_OFFSET("fs_node", "children");
			ld_fte->list_head_offset = 0;

			n2 = do_list(ld_fte);
			if (!dest) {
				fprintf(fp, "\t\tfte number: %d\n", n2 - 1);
			}
			if (no_fte == 0) {
				for (i2 = 1; i2 < n2; ++i2) {
					ulong t2 = ld_fte->list_ptr[i2];
					if (!dest) {
						fprintf(fp, "\t\tfs_fte.val,index,action  %lx -x\n", t2);
					}

					ld_rule =  &rule;
					BZERO(ld_rule, sizeof(struct list_data));
					ld_rule->flags |= LIST_ALLOCATE;

					ld_rule->start = ld_rule->end = t2 + MEMBER_OFFSET("fs_node", "children");
					ld_rule->list_head_offset = 0;

					n3 = do_list(ld_rule);

					int start = 1;
/* 					for (i3 = 1; i3 < n3; ++i3) { */
					/* omit flow counter */
					if (dest)
						start = 2;
					for (i3 = start; i3 < n3; ++i3) {
						ulong t3 = ld_rule->list_ptr[i3];
						if (!dest) {
							fprintf(fp, "\t\t\tmlx5_flow_rule.dest_attr %lx -x\n", t3);
						}
						if (dest) {
							ulong dest = t3 + MEMBER_OFFSET("mlx5_flow_rule", "dest_attr");
							print_struct("mlx5_flow_destination", dest);
						}
					}
				}
			}
		}
	} else if (show == 2) {
		for (i1 = 1; i1 < n1; ++i1) {
			ulong t1 = ld_group->list_ptr[i1];
			fprintf(fp, "\tlist -H %lx -s mlx5_flow_group.mask -x\n", ld_group->list_ptr[0]);

			ld_fte =  &fte;
			BZERO(ld_fte, sizeof(struct list_data));
			ld_fte->flags |= LIST_ALLOCATE;

			ld_fte->start = ld_fte->end = t1 + MEMBER_OFFSET("fs_node", "children");
			ld_fte->list_head_offset = 0;

			n2 = do_list(ld_fte);
			fprintf(fp, "\t\tfte number: %d\n", n2 - 1);
			for (i2 = 1; i2 < n2; ++i2) {
				ulong t2 = ld_fte->list_ptr[i2];
				fprintf(fp, "\t\tlist -H %lx -s fs_fte.val,index -x\n", ld_fte->list_ptr[0]);

				ld_rule =  &rule;
				BZERO(ld_rule, sizeof(struct list_data));
				ld_rule->flags |= LIST_ALLOCATE;

				ld_rule->start = ld_rule->end = t2 + MEMBER_OFFSET("fs_node", "children");
				ld_rule->list_head_offset = 0;

				n3 = do_list(ld_rule);

/* 				ulong t3 = ld_rule->list_ptr[i3]; */
				fprintf(fp, "\t\t\tlist -H %lx -s mlx5_flow_rule.dest_attr -x\n", ld_rule->list_ptr[0]);
			}
		}
	}

/* 	FREEBUF(ld_group->list_ptr); */
/* 	FREEBUF(ld_fte->list_ptr); */
/* 	FREEBUF(ld_rule->list_ptr); */
}

void
cmd_hash(void)
{
	int c;
	char *addr = NULL;
	char *ptr;
	ulong a;
	int show = 0;
	char *opt_s = NULL;     /* struct */
	char *opt_m = NULL;     /* member */
	int print = 0;
	int offset = -1;

	while ((c = getopt(argcnt, args, "a:s:m:tpo:")) != EOF) {
		switch (c) {
		case 't':       /* for testing */
			show = 1;
			a = 0xffff8809b254c0c0;
			break;
		case 's':
			opt_s = optarg;
			break;
		case 'm':
			opt_m = optarg;
			break;
		case 'p':
			print = 1;
			break;
		case 'o':
			offset = atoi(optarg);
			break;
		default:
			return;
		}
	}

	addr = args[optind];
	if (!addr || !opt_s || !opt_m) {
		fprintf(fp, "hash <address of tbl> -s struct -m member -o offset\n");
		return;
	}

	if (show != 1)
		a = strtoul(addr, &ptr, 16);

	show_hash(a, opt_s, opt_m, print, offset);
}

void show_hash(ulong a, char *opt_s, char *opt_m, int print, int offset)
{
	int i = 0;
	ulong rhash_head;

	a = read_pointer1(a);
	fprintf(fp, "bucket_table %lx -x\n", a);

	unsigned int size = read_pointer2(a, "bucket_table", "size");
	ulong buckets = a + MEMBER_OFFSET("bucket_table", "buckets");

	if (offset < 0)
		offset = MEMBER_OFFSET(opt_s, opt_m);

	fprintf(fp, "size %x, offset %x\n", size, offset);
	fprintf(fp, "buckets %lx\n", buckets);

	for (i = 0; i < size; i++) {
		rhash_head = read_pointer1(buckets + i * 8);
		if (!rhash_head)
			continue;
		while (1)  {
			if (rhash_head & 1)
				break;
			if (print)
				print_struct(opt_s, rhash_head - offset);
			else
				fprintf(fp, "%s %lx\n", opt_s, rhash_head - offset);
			rhash_head = read_pointer1(rhash_head);
		}
	}
}

void show_tcf_proto(ulong tcf_proto, int print)
{
	fprintf(fp, "list tcf_proto.next %lx -s tcf_proto\n", tcf_proto);

	if (!tcf_proto)
		return;

	unsigned short protocol;
	unsigned int prio;
	do {
		prio = ntohl(read_u32(tcf_proto, "tcf_proto", "prio"));
		protocol = ntohs(read_u16(tcf_proto, "tcf_proto", "protocol"));
		fprintf(fp, "\n\t=== %x, %x ===\n", prio, protocol);
		fprintf(fp, "\ttcf_proto %lx\n", tcf_proto);

		ulong cls_fl_head = read_pointer2(tcf_proto, "tcf_proto", "root");
		fprintf(fp, "\tcls_fl_head  %lx\n", cls_fl_head);
		ulong ht = cls_fl_head + MEMBER_OFFSET("cls_fl_head", "ht");
		fprintf(fp, "\thash %lx -s fl_flow_mask -m ht_node\n", ht);

		ulong idr = cls_fl_head + MEMBER_OFFSET("cls_fl_head", "handle_idr");

		if (centos()) {
			int i, count;
			ulong filter, ary;

			fprintf(fp, "\tidr_ext %lx\n", idr);
			ulong idr_layer = read_pointer1(idr);
			if (idr_layer == 0)
				goto next;
			fprintf(fp, "\tidr_layer %lx\n", idr_layer);
			count = read_int(idr_layer, "idr_layer", "count");
			fprintf(fp, "\tcount %d\n", count);
			ary = idr_layer + MEMBER_OFFSET("idr_layer", "ary") + 8;
			i = 0;
			while (i < count) {
				filter = read_pointer1(ary);
				if (filter) {
					if (print)
						print_struct("cls_fl_filter", filter);
					else
						fprintf(fp, "\tcls_fl_filter %lx\n", filter);
					i++;
				}
				ary += 8;
			}
		} else {
			fprintf(fp, "\ttree -t xarray %lx -s cls_fl_filter\n", idr);
		}
next:
		tcf_proto = read_pointer2(tcf_proto, "tcf_proto", "next");
	} while (tcf_proto);
}

int centos72(void)
{
	struct new_utsname *uts;
	uts = &kt->utsname;
	if (strncmp(uts->release, "3.10.0-327", 10) == 0)
		return 1;
	return 0;
}

int kernel49(void)
{
	struct new_utsname *uts;
	uts = &kt->utsname;
	if (strncmp(uts->release, "4.9", 3) == 0)
		return 1;
	return 0;
}

int centos(void)
{
	struct new_utsname *uts;
	uts = &kt->utsname;
	if (strncmp(uts->release, "3.10.0", 6) == 0)
		return 1;
	return 0;
}

void show_ingress(ulong net_addr)
{
	struct list_data chain, *ld;
	int print = 0;
	int c, i, n;
	ulong tcf_proto;
	ulong tcf_chain;

	while ((c = getopt(argcnt, args, "p")) != EOF) {
		switch (c) {
		case 'p':
			print = 1;
			break;
		default:
			return;
		}
	}

	ulong ingress_queue = read_pointer2(net_addr, "net_device", "ingress_queue");
	fprintf(fp, "net_device.ingress_queue\n");
	fprintf(fp, "netdev_queue  %lx\n", ingress_queue);

	if (!ingress_queue)
		return;

	if (centos72()) {
		fprintf(fp, "for centos 7.2\n");
		ulong qdisc_sleep = read_pointer2(ingress_queue, "netdev_queue", "qdisc_sleeping");
		fprintf(fp, "Qdisc %lx\n", qdisc_sleep);
		ulong ingress_qdisc_data = qdisc_sleep + STRUCT_SIZE("Qdisc");
		fprintf(fp, "ingress_qdisc_data %lx\n", ingress_qdisc_data);
		tcf_proto = read_pointer1(qdisc_sleep + STRUCT_SIZE("Qdisc"));
		show_tcf_proto(tcf_proto, print);
		return;
	} else if (kernel49()) {
		fprintf(fp, "for kernel 4.9\n");
		tcf_proto = read_pointer2(net_addr, "net_device", "ingress_cl_list");
		show_tcf_proto(tcf_proto, print);
		return;
	}

	// qdisc_priv()
	ulong qdisc = read_pointer2(ingress_queue, "netdev_queue", "qdisc");
	fprintf(fp, "Qdisc  %lx\n", qdisc);
	ulong ingress_sched_data = qdisc + STRUCT_SIZE("Qdisc");
	fprintf(fp, "ingress_sched_data  %lx\n", ingress_sched_data);
	ulong tcf_block = read_pointer2(ingress_sched_data, "ingress_sched_data", "block");
	fprintf(fp, "tcf_block  %lx\n", tcf_block);

	if (!tcf_block)
		return;

	ulong cb_list = tcf_block + MEMBER_OFFSET("tcf_block", "cb_list");
	fprintf(fp, "list -H %lx -s tcf_block_cb -o tcf_block_cb.list\n", cb_list);

	// struct net_device		->	ingress_queue
	// struct netdev_queue		->	qdisc
	// struct Qdisc			->	ingress_sched_data
	// struct ingress_sched_data	->	block
	// struct tcf_block		->	chain_list
	// struct tcf_chain		->	tcf_proto
	// struct tcf_proto		->	root
	// struct cls_fl_head		->	handle_idr

	ulong chain_list = tcf_block + MEMBER_OFFSET("tcf_block", "chain_list");
	fprintf(fp, "list -H %lx -o tcf_chain.list -s tcf_chain\n", chain_list);

	ulong miniq = read_pointer2(net_addr, "net_device", "miniq_ingress");
	if (miniq) {
		fprintf(fp, "\nmini_Qdisc  %lx\n", miniq);
		tcf_proto = read_pointer2(miniq, "mini_Qdisc", "filter_list");
		fprintf(fp, "tcf_proto %lx\n", tcf_proto);
	}

	ld =  &chain;
	BZERO(ld, sizeof(struct list_data));
	ld->flags |= LIST_ALLOCATE;
	ld->start = ld->end = chain_list;
	ld->list_head_offset = MEMBER_OFFSET("tcf_chain", "list");
	n = do_list(ld);
	for (i = 1; i < n; i++) {
		unsigned short index;

		tcf_chain = ld->list_ptr[i];
		fprintf(fp, "\ntcf_chain %lx\n", tcf_chain);
		index = read_u32(tcf_chain, "tcf_chain", "index");
		fprintf(fp, "====== chain %x ======\n", index);

		tcf_proto = read_pointer2(tcf_chain, "tcf_chain", "filter_chain");
		show_tcf_proto(tcf_proto, print);
	}

	FREEBUF(ld->list_ptr);
}

static void show_mlx5e_attach_encap(ulong mlx5_esw_offload)
{
	ulong encap_tbl = mlx5_esw_offload + MEMBER_OFFSET("mlx5_esw_offload", "encap_tbl");
	ulong head, entry, pkt_reformat, flows;
	int i;

	fprintf(fp, "encap_tbl  %lx\n", encap_tbl);
	for (i = 0; i < 256; i++) {
		head = read_pointer1(encap_tbl + i * 8);
		if (head) {
			fprintf(fp, "list %lx -s mlx5e_encap_entry -l mlx5e_encap_entry.encap_hlist\n", head);
			entry = head - MEMBER_OFFSET("mlx5e_encap_entry", "encap_hlist");
			pkt_reformat = entry + MEMBER_OFFSET("mlx5e_encap_entry", "pkt_reformat");
			pkt_reformat = read_pointer1(pkt_reformat);
			fprintf(fp, "mlx5e_encap_entry %lx\n", entry);
/* 			print_struct("mlx5_pkt_reformat", pkt_reformat); */
			flows = entry + MEMBER_OFFSET("mlx5e_encap_entry", "flows");
			fprintf(fp, "list %lx -s encap_flow_item -l encap_flow_item.list\n", flows);
		}
	}
}

void show_eswitch(ulong esw)
{
	int i;

	if (!esw)
		return;

	fprintf(fp, "mlx5_eswitch  %lx\n", esw);
	fprintf(fp, "mlx5_eswitch.manager_vport,total_vports,enabled_vports,mode %lx\n", esw);

	ulong vports = read_pointer2(esw, "mlx5_eswitch", "vports");
	fprintf(fp, "mlx5_vport  %lx\n", vports);
	fprintf(fp, "mlx5_vport  %lx\n", vports + STRUCT_SIZE("mlx5_vport"));
	fprintf(fp, "mlx5_vport  %lx\n", vports + STRUCT_SIZE("mlx5_vport") * 2);

	ulong offloads = esw + MEMBER_OFFSET("mlx5_eswitch", "offloads");
	fprintf(fp, "mlx5_esw_offload  %lx\n", offloads);
	show_mlx5e_attach_encap(offloads);

	fprintf(fp, "repeat -1 mlx5_esw_offload.num_flows -d %lx\n", offloads);

	ulong vport_to_tir = read_pointer2(offloads, "mlx5_esw_offload", "ft_offloads");
	fprintf(fp, "flow %lx # vport_to_tir flow table\n", vport_to_tir);

	ulong encap_tbl = offloads + MEMBER_OFFSET("mlx5_esw_offload", "encap_tbl");
	ulong mod_hdr = offloads + MEMBER_OFFSET("mlx5_esw_offload", "mod_hdr");
	ulong mod_hdr_tbl = mod_hdr + MEMBER_OFFSET("mod_hdr_tbl", "hlist");
	fprintf(fp, "encap_tbl  %lx\n", encap_tbl);
	fprintf(fp, "mod_hdr_tbl hlist %lx\n", mod_hdr_tbl);
	for (i = 0; i < 256; i++) {
		ulong t = read_pointer1(mod_hdr_tbl + i * 8);
		if (t)
			fprintf(fp, "list %lx -s mlx5e_mod_hdr_entry -l mlx5e_mod_hdr_entry.mod_hdr_hlist\n", t);
	}

	ulong mlx5_eswitch_fdb = esw + MEMBER_OFFSET("mlx5_eswitch", "fdb_table");
	fprintf(fp, "mlx5_eswitch_fdb  %lx\n\n", mlx5_eswitch_fdb);

	ulong fdb_table = read_pointer1(mlx5_eswitch_fdb);
	ulong fwd_table = read_pointer1(mlx5_eswitch_fdb + 8);
	fprintf(fp, "flow %lx\n", fdb_table);
	fprintf(fp, "fwd_table\n");
	fprintf(fp, "flow %lx\n\n", fwd_table);
	fprintf(fp, "flow -c %lx\n", fdb_table);
	fprintf(fp, "repeat -1 flow -c %lx\n", fdb_table);
	fprintf(fp, "flow %lx -d\n", fdb_table);
}

void show_namespace(ulong mlx5_flow_steering)
{
	ulong fdb_root_fs = read_pointer2(mlx5_flow_steering, "mlx5_flow_steering", "fdb_root_ns");
	fprintf(fp, "fdb_root_fs\n");
	fprintf(fp, "mlx5_flow_root_namespace  %lx\n", fdb_root_fs);
	fprintf(fp, "list -H %lx -s fs_prio.num_levels,start_level,prio,num_ft,node.type\n", fdb_root_fs + 0x10);

	ulong root_fs = read_pointer2(mlx5_flow_steering, "mlx5_flow_steering", "root_ns");
	fprintf(fp, "root_fs\n");
	fprintf(fp, "mlx5_flow_root_namespace  %lx\n", root_fs);
	fprintf(fp, "list -H %lx -s fs_prio.num_levels,start_level,prio,num_ft,node.type\n", root_fs + 0x10);
}

void show_mdev(ulong mdev)
{
	fprintf(fp, "mlx5_core_dev  %lx\n", mdev);

	ulong mlx5_priv = mdev + MEMBER_OFFSET("mlx5_core_dev", "priv");
	fprintf(fp, "mlx5_priv  %lx\n", mlx5_priv);

	ulong mlx5_flow_steering = read_pointer2(mlx5_priv, "mlx5_priv", "steering");
	fprintf(fp, "mlx5_flow_steering  %lx\n", mlx5_flow_steering);

	show_namespace(mlx5_flow_steering);

	ulong mlx5_lag = read_pointer2(mlx5_priv, "mlx5_priv", "lag");
	fprintf(fp, "mlx5_lag  %lx\n", mlx5_lag);

	ulong fc_stats = mlx5_priv + MEMBER_OFFSET("mlx5_priv", "fc_stats");
	fprintf(fp, "mlx5_fc_stats  %lx\n", fc_stats);
	fprintf(fp, "tree -t rbtree -r mlx5_fc.node %lx -o 0 -s mlx5_fc.lastpackets,lastbytes\n", fc_stats);

	ulong eq_table = mlx5_priv + MEMBER_OFFSET("mlx5_priv", "eq_table");
	fprintf(fp, "mlx5_eq_table  %lx\n", eq_table);

	ulong eqs_list = eq_table + MEMBER_OFFSET("mlx5_eq_table", "comp_eqs_list");
	fprintf(fp, "list -H %lx -o mlx5_eq.list -s mlx5_eq\n", eqs_list);

	ulong esw = read_pointer2(mlx5_priv, "mlx5_priv", "eswitch");
	show_eswitch(esw);
}

#define ALIGN(size, align) ((size + align - 1) & (~(align - 1)))

void show_mlx(ulong net_addr)
{
	ulong mlx5e_priv = net_addr + ALIGN(SIZE(net_device), 32);
	int i;

	fprintf(fp, "mlx5e_priv  %lx\n", mlx5e_priv);

	fprintf(fp, "list -H mlx5_dev_list -l mlx5_priv.dev_list -s mlx5_priv.name\n");
	fprintf(fp, "list -H intf_list -l mlx5_interface.list -s mlx5_interface\n");

	/*
	 * struct mlx5e_vxlan {
	 *   udp_port = 0x12b5
	 * }
	 */
	ulong vxlan = mlx5e_priv +  MEMBER_OFFSET("mlx5e_priv", "vxlan") +  MEMBER_OFFSET("mlx5e_vxlan_db", "tree");
	fprintf(fp, "tree -t ra %lx -s mlx5e_vxlan\n", vxlan);

	ulong fs = mlx5e_priv + MEMBER_OFFSET("mlx5e_priv", "fs");
	fprintf(fp, "mlx5e_flow_steering  %lx\n", fs);

	ulong tc = fs + MEMBER_OFFSET("mlx5e_flow_steering", "tc");
	fprintf(fp, "mlx5e_tc_table  %lx\n", tc);
/* 	ulong ht = read_pointer2(tc, "mlx5e_tc_table", "ht"); */
	/* for old kernel before 4.17.0-rc3+ */
/* 	fprintf(fp, "hash %lx -s mlx5e_tc_flow -m node\n", ht); */
	/* mlx5e_tc_flow.cookie the address of cls_fl_filter */

	ulong  ppriv = read_pointer2(mlx5e_priv, "mlx5e_priv", "ppriv");
/* 	fprintf(fp, "mlx5_eswitch_rep  %lx\n", ppriv); */

	/* in VM/VF, ppriv is NULL */
	if (ppriv != 0) {
		fprintf(fp, "mlx5e_rep_priv  %lx\n", ppriv);
		ulong tc_ht = ppriv + MEMBER_OFFSET("mlx5e_rep_priv", "tc_ht");
		fprintf(fp, "hash %lx -s mlx5e_tc_flow -m node\n", tc_ht);
		ulong neigh_update = ppriv + MEMBER_OFFSET("mlx5e_rep_priv", "neigh_update");
		fprintf(fp, "mlx5e_neigh_update_table  %lx\n", neigh_update);
		ulong neigh_list = neigh_update + MEMBER_OFFSET("mlx5e_neigh_update_table", "neigh_list");
		fprintf(fp, "list -H %lx -l mlx5e_neigh_hash_entry.neigh_list -s mlx5e_neigh_hash_entry\n", neigh_list);
		ulong neigh_ht = neigh_update + MEMBER_OFFSET("mlx5e_neigh_update_table", "neigh_ht");
		fprintf(fp, "hash %lx -s mlx5e_neigh_hash_entry -m rhash_node\n", neigh_ht);

		ulong rep = read_pointer2(ppriv, "mlx5e_rep_priv", "rep");
		fprintf(fp, "mlx5_eswitch_rep  %lx\n", rep);
		fprintf(fp, "mlx5_eswitch_rep  %lx\n", rep + STRUCT_SIZE("mlx5_eswitch_rep"));
		fprintf(fp, "mlx5_eswitch_rep  %lx\n", rep + STRUCT_SIZE("mlx5_eswitch_rep") * 2);
	}

	ulong mdev = read_pointer2(mlx5e_priv, "mlx5e_priv", "mdev");
	show_mdev(mdev);

	ulong  qdisc = read_pointer2(net_addr, "net_device", "qdisc");
	fprintf(fp, "Qdisc  %lx\n", qdisc);

	ulong  txq = read_pointer2(qdisc, "Qdisc", "dev_queue");
	fprintf(fp, "tx-0, net_device._tx\n");
	fprintf(fp, "netdev_queue %lx\n", txq);

	ulong channels = mlx5e_priv + MEMBER_OFFSET("mlx5e_priv", "channels");
	fprintf(fp, "mlx5e_channels %lx\n", channels);

	int num = read_int(channels, "mlx5e_channels", "num");
	fprintf(fp, "mlx5e_channels num %d\n", num);
	num = 1;
	ulong channels_p = read_pointer2(channels, "mlx5e_channels", "c");

	for (i = 0; i < num; i++) {
		fprintf(fp, "=== %d ===\n", i);
		ulong channel1 = read_pointer1(channels_p + i*8);
		fprintf(fp, "mlx5e_channel.sq %lx\n", channel1);

		ulong mlx5e_ch_stats = read_pointer2(channel1, "mlx5e_channel", "stats");
		fprintf(fp, "mlx5e_ch_stats %lx\n", mlx5e_ch_stats);
		print_struct("mlx5e_ch_stats", mlx5e_ch_stats);

		ulong sq = channel1 + MEMBER_OFFSET("mlx5e_channel", "sq");
		fprintf(fp, "mlx5e_txqsq  %lx\n", sq);

		ulong rq = channel1 + MEMBER_OFFSET("mlx5e_channel", "rq");
		fprintf(fp, "mlx5e_rq  %lx\n", rq);
	}

	show_ingress(net_addr);
}


static ulong
get_netdev_addr(char *name)
{
	ulong task = CURRENT_TASK();
	ulong nsproxy_p, net_ns_p;
	struct list_data list_data, *ld;
	char *net_device_buf;
	char *buf;
	long buflen = BUFSIZE;
	int ndevcnt, i;
	long flen;
	ulong netdev_addr = 0;

	if (!net->netdevice) /* initialized in net_init() */
		return 0;

	buf = GETBUF(buflen);
	flen = MAX(VADDR_PRLEN, strlen(net->netdevice));

	net_device_buf = GETBUF(SIZE(net_device));

	ld =  &list_data;
	BZERO(ld, sizeof(struct list_data));
	ld->flags |= LIST_ALLOCATE;
	if (VALID_MEMBER(nsproxy_net_ns)) {
		readmem(task + OFFSET(task_struct_nsproxy), KVADDR, &nsproxy_p,
			sizeof(ulong), "task_struct.nsproxy", FAULT_ON_ERROR);
		if (!readmem(nsproxy_p + OFFSET(nsproxy_net_ns), KVADDR, &net_ns_p,
			sizeof(ulong), "nsproxy.net_ns", RETURN_ON_ERROR|QUIET))
			error(FATAL, "cannot determine net_namespace location!\n");
	} else
		net_ns_p = symbol_value("init_net");
	ld->start = ld->end = net_ns_p + OFFSET(net_dev_base_head);
	ld->list_head_offset = OFFSET(net_device_dev_list);

	ndevcnt = do_list(ld);

	/*
	 *  Skip the first entry (init_net).
	 */
	for (i = 1; i < ndevcnt; ++i) {
		char *netdev_addr_str;
		char *ptr;

		get_device_name(ld->list_ptr[i], buf);
		if (!strncmp(buf, name, buflen)) {
			readmem(ld->list_ptr[i], KVADDR, net_device_buf,
				SIZE(net_device), "net_device buffer",
				FAULT_ON_ERROR);

			netdev_addr_str = mkstring(buf, flen, CENTER|RJUST|LONG_HEX,
				MKSTR(ld->list_ptr[i]));

			netdev_addr = strtoul(netdev_addr_str, &ptr, 16);
			goto found;
		}
	}

found:
	FREEBUF(ld->list_ptr);
	FREEBUF(net_device_buf);
	FREEBUF(buf);

	return netdev_addr;
}

void
cmd_mlx(void)
{
	char *ptr;
	char *name = NULL;
	ulong addr;

	name = args[1];
	if (name == NULL) {
		fprintf(fp, "name is NULL\n");
		return;
	}

	if (strstr(name, "ffff88"))
		addr = strtoul(name, &ptr, 16);
	else
		addr = get_netdev_addr(name);
	if (addr)
		show_mlx(addr);
}

void show_hash_miniflow(ulong a, char *opt_s, char *opt_m, int print, int offset)
{
	int i = 0;
	ulong rhash_head;

	a = read_pointer1(a);
	fprintf(fp, "bucket_table %lx -x\n", a);

	unsigned int size = read_pointer2(a, "bucket_table", "size");
	ulong buckets = a + MEMBER_OFFSET("bucket_table", "buckets");

	if (offset < 0)
		offset = MEMBER_OFFSET(opt_s, opt_m);

	fprintf(fp, "size %x, offset %x\n", size, offset);
	fprintf(fp, "buckets %lx\n", buckets);

	for (i = 0; i < size; i++) {
		rhash_head = read_pointer1(buckets + i * 8);
		while (1)  {
			if (rhash_head & 1)
				break;

			long tuple = rhash_head + MEMBER_OFFSET("flow_offload_tuple_rhash", "tuple");
			fprintf(fp, "nf_conntrack_tuple %lx\n", tuple);
			char dir = read_char(tuple + 0x27);
			fprintf(fp, "dir %d\n", dir);
			long offset2 = 0;
			if (dir == 1)
				offset2 = STRUCT_SIZE("flow_offload_tuple_rhash");
			if (print)
				print_struct(opt_s, rhash_head - offset);
			else {
				fprintf(fp, "%s %lx\n", opt_s, rhash_head - offset);
				long entry = rhash_head - offset2;
				fprintf(fp, "flow_offload_entry %lx\n", entry);
				long deps = entry + MEMBER_OFFSET("flow_offload_entry", "deps");
				fprintf(fp, "list -H %lx -s mlx5e_tc_flow.priv -l mlx5e_tc_flow.nft_node\n", deps);
			}
			rhash_head = read_pointer1(rhash_head);
		}
	}
}

void
cmd_miniflow(void)
{
	long table = symbol_value("_flowtable");
	table = read_pointer1(table);
	fprintf(fp, "flow_offload_table %lx\n", table);

	long rht = table + MEMBER_OFFSET("flow_offload_table", "rhashtable");
	show_hash_miniflow(rht, "flow_offload_tuple_rhash", "node", 0, 0);
/* 	fprintf(fp, "hash %lx -s flow_offload_tuple_rhash -m node -o 0\n", rht); */
}

void
cmd_pci(void)
{
	char *name = "mlx5_core_driver";
	struct list_data devices, *ld;
	int i, n;

	if (args[1] != NULL)
		name = args[1];

	long mlx5_core_driver = symbol_value(name);
	fprintf(fp, "pci_driver  %lx\n", mlx5_core_driver);

	long device_driver = mlx5_core_driver + MEMBER_OFFSET("pci_driver", "driver");
	fprintf(fp, "device_driver  %lx\n", device_driver);

	long driver_private = read_pointer2(device_driver, "device_driver", "p");
	fprintf(fp, "driver_private  %lx\n", driver_private);

	long klist_devices = driver_private + MEMBER_OFFSET("driver_private", "klist_devices");
	fprintf(fp, "klist  %lx\n", klist_devices);

	long k_list = klist_devices + MEMBER_OFFSET("klist", "k_list");
	fprintf(fp, "list -H  %lx\n", k_list);

	ld =  &devices;
	BZERO(ld, sizeof(struct list_data));
	ld->flags |= LIST_ALLOCATE;
	ld->start = ld->end = k_list;

	ld->list_head_offset = MEMBER_OFFSET("device_private", "knode_driver") +
				+ MEMBER_OFFSET("klist_node", "n_node");
	n = do_list(ld);
	for (i = 1; i < n; i++) {
		long private = ld->list_ptr[i];
		long device = read_pointer2(private, "device_private", "device");
		long pci_dev = device - MEMBER_OFFSET("pci_dev", "dev");
		long driver_data = read_pointer2(device, "device", "driver_data");
		long driver = read_pointer2(device, "device", "driver");
		long kobj = device + MEMBER_OFFSET("device", "kobj");
		long name = read_pointer2(kobj, "kobject", "name");
		char buf[32];

		fprintf(fp, "\ndevice_private %lx\n", private);
		fprintf(fp, "device %lx\n", device);
		fprintf(fp, "pci_dev %lx\n", pci_dev);
		fprintf(fp, "device_driver %lx\n", driver);
		fprintf(fp, "kobject %lx\n", kobj);
		read_string(name, buf, 32);
		fprintf(fp, "name %s\n", buf);
		fprintf(fp, "mlx5_core_dev %lx\n", driver_data);
	}

	FREEBUF(ld->list_ptr);

}

#if 0
	# example to print list
	struct list_data devices, *ld;
	int i, n;

	ld =  &devices;
	BZERO(ld, sizeof(struct list_data));
	ld->flags |= LIST_ALLOCATE;
	ld->start = ld->end = k_list;
	ld->list_head_offset = 0x70;
	n = do_list(ld);
	for (i = 1; i < n; i++) {
		long device;

		device = ld->list_ptr[i];
		fprintf(fp, "device %lx\n", device);
	}

	FREEBUF(ld->list_ptr);
#endif

void
cmd_bus(void)
{
	int all = 0;

	if (args[1] != NULL && !strcmp(args[1], "all"))
		all = 1;

	struct list_data devices, *ld;
	char *name = "pci_bus_type";
	int i, n, print = 1;

	long pci_bus_type = symbol_value(name);
	fprintf(fp, "pci_bus_type\n");
	fprintf(fp, "bus_type %lx\n", pci_bus_type);

	long p = read_pointer2(pci_bus_type, "bus_type", "p");
	fprintf(fp, "subsys_private  %lx\n", p);

	long klist_devices = p + MEMBER_OFFSET("subsys_private", "klist_devices");
	fprintf(fp, "klist %lx\n", klist_devices);

	long k_list = klist_devices + MEMBER_OFFSET("klist", "k_list");
	fprintf(fp, "list -H %lx\n", k_list);

	int offset = MEMBER_OFFSET("pci_driver", "driver");
	long iwl_pci_driver = symbol_exists("iwl_pci_driver") ?
				symbol_value("iwl_pci_driver") : 0;
	long iwl_device_driver = iwl_pci_driver + offset;
	long mlx5_core_driver = symbol_exists("mlx5_core_driver") ?
				symbol_value("mlx5_core_driver") : 0;
	long mlx5_device_driver = mlx5_core_driver + offset;

	ld =  &devices;
	BZERO(ld, sizeof(struct list_data));
	ld->flags |= LIST_ALLOCATE;
	ld->start = ld->end = k_list;
	/*
	 * bus_add_device()
	 *	klist_add_tail(&dev->p->knode_bus, &bus->p->klist_devices);
	*/
	ld->list_head_offset = MEMBER_OFFSET("device_private", "knode_bus") +
				+ MEMBER_OFFSET("klist_node", "n_node");
	n = do_list(ld);
	for (i = 1; i < n; i++) {
		long private = ld->list_ptr[i];
		long device = read_pointer2(private, "device_private", "device");
		long pci_dev = device - MEMBER_OFFSET("pci_dev", "dev");
		long driver_data;

		if (!centos()) {
			driver_data = read_pointer2(device, "device", "driver_data");
		} else {
			p = read_pointer2(device, "device", "p");
			driver_data = read_pointer2(p, "device_private", "driver_data");
		}

		long driver = read_pointer2(device, "device", "driver");
		long kobj = device + MEMBER_OFFSET("device", "kobj");
		long name = read_pointer2(kobj, "kobject", "name");
		char buf[32];

		if (all || driver == iwl_device_driver || driver == mlx5_device_driver) {
			if (!all && print && driver == iwl_device_driver)
				fprintf(fp, "\niwl_pci_driver:\npci_driver %lx\n",
					iwl_pci_driver);
			if (!all && print && driver == mlx5_device_driver)
				fprintf(fp, "\nmlx5_core_driver:\npci_driver %lx\n",
					mlx5_core_driver);
			print = 0;
			if (driver) {
				long driver_name = read_pointer2(driver, "device_driver", "name");
				long mod_name = read_pointer2(driver, "device_driver", "mod_name");
				read_string(name, buf, 32);
				fprintf(fp, "\nname:\t\t%s\n", buf);

				read_string(driver_name, buf, 32);
				fprintf(fp, "driver_name:\t%s\n", buf);
				read_string(mod_name, buf, 32);
				fprintf(fp, "mod_name:\t%s\n", buf);

				fprintf(fp, "device_private %lx\n", private);
				fprintf(fp, "device %lx\n", device);
				fprintf(fp, "pci_dev %lx\n", pci_dev);
				fprintf(fp, "device_driver %lx\n", driver);

				fprintf(fp, "kobject %lx\n", kobj);
				if (driver == iwl_device_driver)
					fprintf(fp, "iwl_trans %lx\n", driver_data);
				if (driver == mlx5_device_driver)
					fprintf(fp, "mlx5_core_dev %lx\n", driver_data);
			}
		}
	}

	FREEBUF(ld->list_ptr);
}

void
cmd_mdev(void)
{
	char *ptr;
	char *name = NULL;
	ulong addr;

	name = args[1];
	if (name == NULL) {
		fprintf(fp, "name is NULL\n");
		return;
	}

	addr = strtoul(name, &ptr, 16);
	if (addr)
		show_mdev(addr);
}

void
cmd_ingress(void)
{
	char *name = NULL;
	ulong addr;

	name = args[1];
	if (name == NULL) {
		fprintf(fp, "name is NULL\n");
		return;
	}

	addr = get_netdev_addr(name);
	if (addr)
		show_ingress(addr);
	else
		fprintf(fp, "name: %s, addr: %lx\n", name, addr);

}

void
cmd_tc(void)
{
	int c;
	char *index = NULL;
	int i = 0;
	int eg = 0;
	int help = 0, print = 0;
	ulong net_ns_p = symbol_value("init_net");

	while ((c = getopt(argcnt, args, "i:eph")) != EOF) {
		switch (c) {
		case 'i':
			index = optarg;
			i = atoi(index);
			break;
		case 'e':
			eg = 1;
			i = read_pointer1(symbol_value("tcf_action_net_id"));
			fprintf(fp, "tcf_action_net_id: %d\n", i);
			break;
		case 'p':
			print = 1;
			break;
		case 'h':
			help = 1;
		break;
			default:
			return;
		}
	}

	if (help || !i) {
		fprintf(fp, "mirred_net_id: %ld\n",
			read_pointer1(symbol_value("mirred_net_id")));
		fprintf(fp, "vxlan_net_id\n");
		fprintf(fp, "vlan_net_id\n");
		fprintf(fp, "tunnel_key_net_id: %ld\n",
			read_pointer1(symbol_value("tunnel_key_net_id")));
		fprintf(fp, "vxlan_net_id\n");
		fprintf(fp, "tcf_action_net_id: %ld\n",
			read_pointer1(symbol_value("tcf_action_net_id")));

		fprintf(fp, "-l tc_action.tcfa_head -s tc_action\n");
		fprintf(fp, "-l tc_action.tcfa_head -s tcf_mirred\n");
		fprintf(fp, "-l tc_action.tcfa_head -s tcf_vlan\n");
		fprintf(fp, "-l tc_action.tcfa_head -s tcf_tunnel_key\n");
		return;
	}

	ulong gen = read_pointer2(net_ns_p, "net", "gen");
	fprintf(fp, "struct net_generic %lx\n", gen);
	ulong ptr = gen + MEMBER_OFFSET("net_generic", "ptr");
	fprintf(fp, "ptr: %lx\n", ptr);
	if (centos())
		i--;
	ulong tc_action_net = read_pointer1(ptr + i * 8);

/* 	fprintf(fp, "eg %d, i: %d\n", eg, i); */
	if (eg) {
		fprintf(fp, "tcf_action_net %lx\n", tc_action_net);
		fprintf(fp, "list -H cb_list -s tcf_action_egdev_cb\n");
		fprintf(fp, "================================\n");
		show_hash(tc_action_net, "tcf_action_egdev", "ht_node", 0, -1);
		if (print) {
			fprintf(fp, "================================\n");
			show_hash(tc_action_net, "tcf_action_egdev", "ht_node", 1, -1);
		}
	} else {
		fprintf(fp, "tc_action_net %lx\n", tc_action_net);

		ulong tcf_idrinfo = read_pointer1(tc_action_net);
		fprintf(fp, "tcf_idrinfo %lx\n", tcf_idrinfo);
		ulong idr = tcf_idrinfo + MEMBER_OFFSET("tcf_idrinfo", "action_idr");

		fprintf(fp, "idr  %lx\n", idr);
		ulong radix = read_pointer2(idr, "radix_tree_root", "rnode");
		fprintf(fp, "radix_tree_node  %lx\n", radix & ~1UL);
		fprintf(fp, "\ntree -t ra %lx -s tc_action\n", idr);
		fprintf(fp, "tree -t ra %lx -s tc_action.tcfa_refcnt\n", idr);
		fprintf(fp, "repeat tree -t ra %lx -s tc_action.tcfa_refcnt\n", idr);
	}
}

void
cmd_array(void)
{
	char *addr = NULL, *s = NULL, *number = NULL, *member = NULL;
	int print = 0, help = 0;
	int c, n, i;
	ulong a;

	while ((c = getopt(argcnt, args, "s:n:m:ph")) != EOF) {
		switch (c) {
		case 'n':
			number = optarg;
			break;
		case 's':
			s = optarg;
			break;
		case 'm':
			member = optarg;
			break;
		case 'p':
			print = 1;
			break;
		case 'h':
			help = 1;
			break;
		default:
			return;
		}
	}

	addr = args[optind];
	if (help || !addr | !number || !s) {
		fprintf(fp, "net\n");
		fprintf(fp, "net_device._tx ffff881025280000\n");
		fprintf(fp, "array ffff881025280000 -s netdev_queue -n 16 -p\n");
		fprintf(fp, "array ffff881025280000 -s netdev_queue -n 16 -m kobj\n");
		return;
	}

	a = strtoul(addr, NULL, 16);
	n = atoi(number);

	for (i = 0; i < n; i ++) {
		ulong new = a + i * STRUCT_SIZE(s);
		if (member)
			fprintf(fp, "%s.%s %lx\n", s, member, new);
		else {
			if (print)
				print_struct(s, new);
			else
				fprintf(fp, "%s %lx\n", s, new);
		}
	}
}

void
cmd_rtnl(void)
{
	ulong handlers = read_pointer1(symbol_value("rtnl_msg_handlers"));

	fprintf(fp, "array %lx -s rtnl_link -n 50 -p\n", handlers);

	handlers = read_pointer1(symbol_value("rtnl_msg_handlers") + 0x10);
	fprintf(fp, "array %lx -s rtnl_link -n 50 -p\n", handlers);
}

void show_flow_hash(ulong a)
{
	ulong rhash_head, offset, mlx5e_tc_flow, attr, esw_attr;
	char *opt_s = "mlx5e_tc_flow";
	char *opt_m = "node";
	int i = 0;

	a = read_pointer1(a);
	fprintf(fp, "bucket_table %lx -x\n", a);

	unsigned int size = read_pointer2(a, "bucket_table", "size");
	ulong buckets = a + MEMBER_OFFSET("bucket_table", "buckets");

	offset = MEMBER_OFFSET(opt_s, opt_m);
	fprintf(fp, "size %x, offset %x\n", size, offset);
	fprintf(fp, "buckets %lx\n", buckets);

	for (i = 0; i < size; i++) {
		rhash_head = read_pointer1(buckets + i * 8);
		if (!rhash_head)
			continue;
		while (1)  {
			if (rhash_head & 1)
				break;

			mlx5e_tc_flow = rhash_head - offset;
			fprintf(fp, "mlx5e_tc_flow %lx\n", mlx5e_tc_flow);
/* 			print_struct("mlx5e_tc_flow", mlx5e_tc_flow); */

			attr = read_pointer2(mlx5e_tc_flow, "mlx5e_tc_flow", "attr");
			fprintf(fp, "mlx5_flow_attr %lx\n", attr);
/* 			print_struct("mlx5_flow_attr", attr); */

			esw_attr = attr + MEMBER_OFFSET("mlx5_flow_attr", "esw_attr");
			fprintf(fp, "mlx5_esw_flow_attr %lx\n", esw_attr);
/* 			print_struct("mlx5_esw_flow_attr", esw_attr); */

			rhash_head = read_pointer1(rhash_head);
		}
	}
}

static void
show_flow(ulong net_addr)
{
	ulong mlx5e_priv = net_addr + SIZE(net_device);
	int i;

	fprintf(fp, "mlx5e_priv  %lx\n", mlx5e_priv);
	ulong  ppriv = read_pointer2(mlx5e_priv, "mlx5e_priv", "ppriv");
	if (ppriv != 0) {
		fprintf(fp, "mlx5e_rep_priv  %lx\n", ppriv);
		ulong tc_ht = ppriv + MEMBER_OFFSET("mlx5e_rep_priv", "tc_ht");
		show_flow_hash(tc_ht);
	}
}

void
cmd_flow(void)
{
	char *ptr;
	char *name = NULL;
	ulong addr;

	name = args[1];
	if (name == NULL) {
		fprintf(fp, "name is NULL\n");
		return;
	}

	if (strstr(name, "ffff88"))
		addr = strtoul(name, &ptr, 16);
	else
		addr = get_netdev_addr(name);
	if (addr)
		show_flow(addr);
}
