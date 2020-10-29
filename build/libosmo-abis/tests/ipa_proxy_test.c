#include <stdio.h>
#include <osmocom/core/talloc.h>
#include <osmocom/abis/abis.h>
#include <osmocom/abis/e1_input.h>
#include <osmocom/abis/ipa_proxy.h>
#include <osmocom/core/logging.h>
#include <osmocom/core/application.h>
#include <osmocom/vty/vty.h>
#include <osmocom/vty/command.h>
#include <osmocom/vty/telnet_interface.h>

static void *tall_test;

#define DIPA_PROXY_TEST 0

struct log_info_cat ipa_proxy_test_cat[] = {
	[DIPA_PROXY_TEST] = {
		.name = "DLINP_IPA_PROXY_TEST",
		.description = "IPA proxy test",
		.color = "\033[1;35m",
		.enabled = 1, .loglevel = LOGL_NOTICE,
	},
};

const struct log_info ipa_proxy_test_log_info = {
	.filter_fn = NULL,
	.cat = ipa_proxy_test_cat,
	.num_cat = ARRAY_SIZE(ipa_proxy_test_cat),
};

static struct vty_app_info vty_info = {
	.name		= "ipa-proxy-test",
	.version	= "1.0",
};

#define IPA_PROXY_TEST_TELNET_PORT	4260

int main(void)
{
	tall_test = talloc_named_const(NULL, 1, "ipa proxy test");
	libosmo_abis_init(tall_test);

	osmo_init_logging(&ipa_proxy_test_log_info);

	vty_init(&vty_info);
	ipa_proxy_vty_init();

	telnet_init(tall_test, NULL, IPA_PROXY_TEST_TELNET_PORT);

	LOGP(DIPA_PROXY_TEST, LOGL_NOTICE, "entering main loop\n");

	while (1) {
		osmo_select_main(0);
	}
}
