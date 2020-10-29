#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <osmocom/core/select.h>
#include <osmocom/core/talloc.h>
#include <osmocom/core/msgb.h>
#include <osmocom/core/logging.h>
#include <osmocom/core/application.h>

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
		LOGP(DRS232TEST, LOGL_ERROR, "cannot read from rs232\n");
		return 0;
	}
	LOGP(DRS232TEST, LOGL_DEBUG, "received %d bytes\n", msg->len);

	printf("%s", msg->data);

	msgb_free(msg);
	return 0;
}

static void *tall_test;

int main(void)
{
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
	osmo_rs232_set_read_cb(r, read_cb);

	if (osmo_rs232_open(r) < 0) {
		LOGP(DRS232TEST, LOGL_ERROR, "cannot open rs232\n");
		exit(EXIT_FAILURE);
	}

	LOGP(DRS232TEST, LOGL_NOTICE, "Entering main loop\n");

	while(1) {
		osmo_select_main(0);
	}
}
