#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <arpa/inet.h>
#include <unistd.h>

#include <osmocom/core/select.h>
#include <osmocom/core/talloc.h>
#include <osmocom/core/msgb.h>
#include <osmocom/core/logging.h>
#include <osmocom/core/application.h>
#include <osmocom/core/endian.h>

#include <osmocom/netif/rs232.h>

#define DRS232TEST 0

struct log_info_cat osmo_rs232_test_cat[] = {
	[DRS232TEST] = {
		.name = "DRS232TEST",
		.description = "rs232 test",
		.color = "\033[1;35m",
		.enabled = 1, .loglevel = LOGL_DEBUG,
	},
};

const struct log_info osmo_rs232_test_log_info = {
	.filter_fn = NULL,
	.cat = osmo_rs232_test_cat,
	.num_cat = ARRAY_SIZE(osmo_rs232_test_cat),
};

static struct osmo_rs232 *r;

void sighandler(int foo)
{
	LOGP(DRS232TEST, LOGL_NOTICE, "closing rs232.\n");
	osmo_rs232_close(r);
	osmo_rs232_destroy(r);
	exit(EXIT_SUCCESS);
}

static int read_cb(struct osmo_rs232 *r)
{
	struct msgb *msg;

	LOGP(DRS232TEST, LOGL_DEBUG, "received data from rs232\n");

	msg = msgb_alloc(1024, "rs232/test");
	if (msg == NULL) {
		LOGP(DRS232TEST, LOGL_ERROR, "cannot allocate message\n");
		return 0;
	}
	if (osmo_rs232_read(r, msg) < 0) {
		LOGP(DRS232TEST, LOGL_ERROR, "cannot receive message\n");
		return 0;
	}
	LOGP(DRS232TEST, LOGL_DEBUG, "received %d bytes\n", msg->len);

	printf("received %d bytes ", msg->len);

	int i;
	printf("(");
	for (i=0; i<msg->len; i++)
		printf("\\x%.2x", 0xff & msg->data[i]);
	printf(") %s\n", msg->data);

	msgb_free(msg);

	return 0;
}

static void *tall_test;

/* u-blox6_ReceiverDescriptionProtocolSpec_(GPS.G6-SW-10018).pdf */

/* See Sect 23. */
struct ubx_hdr {
	uint8_t	sync_char1;	/* 0xb5 */
	uint8_t sync_char2;	/* 0x62 */
	uint8_t	class;
	uint8_t	id;
} __attribute__((packed));

static void ubx_header(struct msgb *msg, uint8_t class, uint8_t id)
{
	/* See Sect. 31.24 */
	struct ubx_hdr ubxhdr = {
		.sync_char1	= 0xb5,
		.sync_char2	= 0x62,
		.class		= class,
		.id		= id,
	};
	memcpy(msg->data, &ubxhdr, sizeof(struct ubx_hdr));
	msgb_put(msg, sizeof(struct ubx_hdr));
}

/* See Sect 26. */
static void ubx_checksum(struct msgb *msg, uint8_t *ck)
{
	struct ubx_hdr *ubxhdr = (struct ubx_hdr *)msg->data;
	/* skip sync chars in checksum calculation. */
	uint8_t *buf = ((uint8_t *)ubxhdr) + 2;
	int i;

	memset(ck, 0, sizeof(uint16_t));

	for (i=0; i<msg->len-2; i++) {
		ck[0] += buf[i];
		ck[1] += ck[0];
	}
}

# if OSMO_IS_LITTLE_ENDIAN
# define utohl(x)       (x)
# define utohs(x)       (x)
# define htoul(x)       (x)
# define htous(x)       (x)
# else
#  if OSMO_IS_BIG_ENDIAN
#   define utohl(x)     __bswap_32 (x)
#   define utohs(x)     __bswap_16 (x)
#   define htoul(x)     __bswap_32 (x)
#   define htous(x)     __bswap_16 (x)
#  endif
# endif

static void ubx_payload_start(struct msgb *msg)
{
	uint16_t len = 0;
	/* make room for payload length. */
	memcpy(msg->data + msg->len, &len, sizeof(len));
	msgb_put(msg, sizeof(len));
}

static void ubx_payload_put_u8(struct msgb *msg, uint8_t data)
{
	memcpy(msg->data + msg->len, &data, sizeof(data));
	msgb_put(msg, sizeof(data));
}

static void ubx_payload_put_le16(struct msgb *msg, uint16_t data)
{
	uint16_t le_data = htous(data);
	memcpy(msg->data + msg->len, &le_data, sizeof(data));
	msgb_put(msg, sizeof(data));
}

static void ubx_payload_put_le32(struct msgb *msg, uint32_t data)
{
	uint32_t le_data = htoul(data);
	memcpy(msg->data + msg->len, &le_data, sizeof(data));
	msgb_put(msg, sizeof(data));
}

static void ubx_payload_stop(struct msgb *msg)
{
	uint16_t *length = (uint16_t *) &(msg->data[4]);
	uint8_t checksum[2];

	/* length does not includes the header, ID, length.
	 * note that checksum has not been yet added.
	 */
	*length = htous(msg->len - 6);

	ubx_checksum(msg, checksum);
	memcpy(msg->data + msg->len, checksum, sizeof(checksum));
	msgb_put(msg, sizeof(checksum));
}

static void cfg_prt(void)
{
	struct msgb *msg;

	msg = msgb_alloc(512, "CFG-PRT for USB");
	if (msg == NULL)
		exit(EXIT_FAILURE);

	ubx_header(msg, 0x06, 0x00);	/* CFG-PRT */

	ubx_payload_start(msg);
	ubx_payload_put_u8(msg, 0x03);		/* Port ID is (=3 USB). */
	ubx_payload_put_u8(msg, 0x00);		/* Reserved. */
	ubx_payload_put_le16(msg, 0x0000);	/* TX ready. */
	ubx_payload_put_le32(msg, 0x00000000);	/* Reserved. */
	ubx_payload_put_le32(msg, 0x00000000);	/* Reserved. */
	ubx_payload_put_le16(msg, 0x0003);	/* InProtoMask (NMEA+UBX). */
	ubx_payload_put_le16(msg, 0x0001);	/* OutProtoMask (UBX). */
	ubx_payload_put_le16(msg, 0x0000);	/* Flags. */
	ubx_payload_put_le16(msg, 0x0000);	/* Reserved. */
	ubx_payload_stop(msg);

	int i;
	for (i=0; i<msg->len; i++)
		printf("\\x%.2x", 0xff & msg->data[i]);
	printf("\n");

	if (osmo_rs232_write(r, msg) < 0) {
		LOGP(DRS232TEST, LOGL_ERROR, "cannot write to rs232\n");
		exit(EXIT_FAILURE);
	}
}

static int nmea_checksum(char *nmea_cmd, uint8_t *checksum)
{
	int i, ret = 0;
	uint8_t from, to;
	char *start, *end;

	/* find starting $ */
	start = strtok(nmea_cmd, "$");
	if (start == NULL)
		return -1;

	from = start - nmea_cmd;

	end = strtok(start+1, "*");
	if (end == NULL)
		return -1;

	to = end - nmea_cmd;

	ret = (uint8_t)nmea_cmd[0];
	for (i=from+1; i<to; i++)
		ret ^= (uint8_t)nmea_cmd[i];

	*checksum = ret;

	return 0;
}

static void send_pubx(void)
{
	struct msgb *msg;

	/* See 21.8: UBX,41.
	 *
	 * $PUBX,41,portId,inProto,outProto,baudrate,autobauding*cs
	 *
	 * [in|out]Proto: bit = 0 (ubx), bit = 1 (nmea)
	 *
	 * Sect 4. Serial Communication Ports Description
	 *
	 * 0 DDC
	 * 1 UART1
	 * 2 UART2
	 * 3 USB
	 * 4 SPI
	 * 5 reserved
	 *
	 * The NMEA command below comes without the checksum calculated.
	 */
	char nmea_cmd[128] = "$PUBX,41,3,0001,0001,9600,0*";
	uint8_t checksum;

	if (nmea_checksum(nmea_cmd, &checksum) < 0) {
		LOGP(DRS232TEST, LOGL_ERROR, "error calculating checksum\n");
		exit(EXIT_FAILURE);
	}
	sprintf(nmea_cmd + strlen(nmea_cmd), "%u\r\n", checksum);

	msg = msgb_alloc(300, "rs232/test");
	if (msg == NULL) {
		LOGP(DRS232TEST, LOGL_ERROR, "cannot allocate message\n");
		exit(EXIT_FAILURE);
	}
	memcpy(msg->data, nmea_cmd, strlen(nmea_cmd));
	msgb_put(msg, strlen(nmea_cmd));

	if (osmo_rs232_write(r, msg) < 0) {
		LOGP(DRS232TEST, LOGL_ERROR, "cannot write to rs232\n");
		exit(EXIT_FAILURE);
	}
}

static void cfg_tp5(void)
{
	struct msgb *msg;

	msg = msgb_alloc(512, "CFG-TP5 for USB");
	if (msg == NULL)
		exit(EXIT_FAILURE);

	ubx_header(msg, 0x06, 0x31);		/* CFG-TP5 */

	ubx_payload_start(msg);
	ubx_payload_put_u8(msg, 0x01);		/* TIMEPULSE2 (=1) */
	ubx_payload_put_u8(msg, 0x00);		/* Reserved. */
	ubx_payload_put_le16(msg, 0x0000);	/* Reserved. */
	ubx_payload_put_le16(msg, 0);		/* Antenna Delay (ns) */
	ubx_payload_put_le16(msg, 0);		/* RF Group Delay (ns) */
	ubx_payload_put_le32(msg, 8192000);	/* freqPeriod (Hz/us) */
	ubx_payload_put_le32(msg, 8192000);	/* freqPeriodLoc (Hz/us) */
	ubx_payload_put_le32(msg, 0x80000000);	/* pulseLenRation:
						   1/2^-32 (us() */
	ubx_payload_put_le32(msg, 0x80000000);	/* pulseLenRationLock:
						   1/2^-32 (us() */
	ubx_payload_put_le32(msg, 0);		/* userConfigDelay (ns) */
	ubx_payload_put_le32(msg, (1 << 0) | (1 << 1) | (1 << 2) | (1 << 3));
						/* flags: bits 0, 1 and 3. */
	ubx_payload_stop(msg);

	int i;
	for (i=0; i<msg->len; i++)
		printf("\\x%.2x", 0xff & msg->data[i]);
	printf("\n");

	if (osmo_rs232_write(r, msg) < 0) {
		LOGP(DRS232TEST, LOGL_ERROR, "cannot write to rs232\n");
		exit(EXIT_FAILURE);
	}
}

static int kbd_cb(struct osmo_fd *fd, unsigned int what)
{
        char buf[1024];
        int ret, val;

        ret = read(STDIN_FILENO, buf, sizeof(buf));
	if (ret < 0) {
		LOGP(DRS232TEST, LOGL_ERROR, "cannot write to read from "
					     "keyboard\n");
		exit(EXIT_FAILURE);
	}

	val = atoi(buf);
	switch(val) {
	case 1:
		printf("sending command PUBX to switch to UBX mode\n");
		send_pubx();
		break;
	case 2:
		printf("sending command TP5\n");
		cfg_tp5();
		break;
	case 3:
		printf("sending command CFG-PRT\n");
		cfg_prt();
		break;
	default:
		printf("wrong option: select 1, 2 or 3\n");
		break;
	}
	return 0;
}

int main(void)
{
	struct osmo_fd *kbd_ofd;
	int rc;

	tall_test = talloc_named_const(NULL, 1, "osmo_rs232_test");

	osmo_init_logging(&osmo_rs232_test_log_info);
	log_set_log_level(osmo_stderr_target, LOGL_NOTICE);

	r = osmo_rs232_create(tall_test);
	if (r == NULL) {
		LOGP(DRS232TEST, LOGL_ERROR, "cannot create rs232 object\n");
		exit(EXIT_FAILURE);
	}
	osmo_rs232_set_serial_port(r, "/dev/ttyACM0");
	osmo_rs232_set_baudrate(r, 9600);
	osmo_rs232_set_delay_us(r, 3330);
	osmo_rs232_set_read_cb(r, read_cb);

	if (osmo_rs232_open(r) < 0) {
		LOGP(DRS232TEST, LOGL_ERROR, "cannot open rs232\n");
		exit(EXIT_FAILURE);
	}

	LOGP(DRS232TEST, LOGL_NOTICE, "Entering main loop\n");

        kbd_ofd = talloc_zero(tall_test, struct osmo_fd);
        if (!kbd_ofd) {
                LOGP(DRS232TEST, LOGL_ERROR, "OOM\n");
                exit(EXIT_FAILURE);
        }
        kbd_ofd->fd = STDIN_FILENO;
        kbd_ofd->when = BSC_FD_READ;
        kbd_ofd->data = NULL;
        kbd_ofd->cb = kbd_cb;
        rc = osmo_fd_register(kbd_ofd);
	if (rc < 0) {
		LOGP(DRS232TEST, LOGL_ERROR, "FD Register\n");
		exit(EXIT_FAILURE);
	}

	while(1) {
		osmo_select_main(0);
	}
}
