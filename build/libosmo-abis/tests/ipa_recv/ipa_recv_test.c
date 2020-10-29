/* IPA receive test */

/*
 * (C) 2014 by On-Waves
 * (C) 2014 by sysmocom s.f.m.c. GmbH
 *
 * All Rights Reserved
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU Affero General Public License as published by
 * the Free Software Foundation; either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU Affero General Public License for more details.
 *
 * You should have received a copy of the GNU Affero General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 *
 */

#include <osmocom/abis/e1_input.h>

#include <osmocom/abis/ipa.h>
#include <osmocom/core/utils.h>
#include <osmocom/core/msgb.h>
#include <osmocom/core/logging.h>
#include <osmocom/core/application.h>

#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <err.h>

static const char *ipa_test_messages[] = {
	"Hello IPA",
	"A longer test message. ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789abcdefghijklmnopqrstuvwxyz",
	"Hello again IPA",
	"",
	"Next is empty",
	NULL,
	"Bye",
	"Bye",
};

static void append_ipa_message(struct msgb *msg, int proto, const char *text)
{
	int len = 0;
	unsigned char *l2;

	if (text)
		len = strlen(text) + 1;

	msgb_put_u16(msg, len);
	msgb_put_u8(msg, proto);

	l2 = msgb_put(msg, len);
	if (text)
		strcpy((char *)l2, text);
}

static int receive_messages(int fd, struct msgb **pending_msg)
{
	struct msgb *msg;
	char dummy;
	int rc;
	while (1) {
		if (recv(fd, &dummy, 1, MSG_PEEK) < 1) {
			rc = -EAGAIN;
			break;
		}
		msg = NULL;
		rc = ipa_msg_recv_buffered(fd, &msg, pending_msg);

		fprintf(stderr,
			"ipa_msg_recv_buffered: %d, msg %s NULL, "
			"pending_msg %s NULL\n",
			rc, msg ? "!=" : "==",
			!pending_msg ? "??" : *pending_msg ? "!=" : "==");
		if (pending_msg && !!msg == !!*pending_msg)
			printf( "got msg %s NULL, pending_msg %s NULL, "
				"returned: %s\n",
				msg ?  "!=" : "==",
				*pending_msg ? "!=" : "==",
				rc == 0 ? "EOF" :
				rc > 0 ? "OK" :
				strerror(-rc));
		else if (!pending_msg && rc == -EAGAIN)
			printf( "got msg %s NULL, "
				"returned: %s\n",
				msg ?  "!=" : "==",
				rc == 0 ? "EOF" :
				rc > 0 ? "OK" :
				strerror(-rc));
		if (rc == 0)
			return 0;
		if (rc == -EAGAIN)
			break;
		if (rc < 0) {
			printf("ipa_msg_recv_buffered failed with: %s\n",
			       strerror(-rc));
			return rc;
		}
		printf("got IPA message, size=%d, proto=%d, text=\"%s\"\n",
		       rc, msg->data[2], msg->l2h);
		msgb_free(msg);
	};

	return rc;
}

static int slurp_data(int fd) {
	int rc;
	char buf[256];
	int count = 0;

	do {
		rc = recv(fd, buf, sizeof(buf), 0);
		if (rc <= 0)
			break;

		count += rc;
	} while (1);

	return count;
};

static void test_complete_recv(int do_not_assemble)
{
	int sv[2];
	struct msgb *msg_out = msgb_alloc(4096, "msg_out");
	struct msgb *pending_msg = NULL;
	int rc, i;

	printf("Testing IPA recv with complete messages%s.\n",
	       do_not_assemble ? "" : " with assembling enabled");

	if (socketpair(AF_UNIX, SOCK_STREAM, 0, sv) == -1)
		err(1, "socketpair");

	fcntl(sv[0], F_SETFL, O_NONBLOCK);

	for (i=0; i < ARRAY_SIZE(ipa_test_messages); i++)
		append_ipa_message(msg_out, 200, ipa_test_messages[i]);

	while (msg_out->len > 0) {
		rc = write(sv[1], msg_out->data, msg_out->len);
		if (rc == -1)
			err(1, "write");
		msgb_pull(msg_out, rc);
	}

	for (i=0; i < ARRAY_SIZE(ipa_test_messages); i++) {
		rc = receive_messages(sv[0],
				      do_not_assemble ? NULL : &pending_msg);
		if (pending_msg)
			printf("Unexpected partial message: size=%d\n",
			       pending_msg->len);
		if (rc == 0)
			break;

		if (rc < 0 && rc != -EAGAIN)
			break;
	}

	rc = slurp_data(sv[0]);
	printf("done: unread %d, unsent %d\n", rc, msg_out->len);

	close(sv[1]);
	close(sv[0]);

	msgb_free(msg_out);
	msgb_free(pending_msg);
}


static void test_partial_recv(int do_not_assemble)
{
	int sv[2];
	struct msgb *msg_out = msgb_alloc(4096, "msg_out");
	struct msgb *pending_msg = NULL;
	int rc, i;

	printf("Testing IPA recv with partitioned messages%s.\n",
	       do_not_assemble ? "" : " with assembling enabled");

	if (socketpair(AF_UNIX, SOCK_STREAM, 0, sv) == -1)
		err(1, "socketpair");

	fcntl(sv[0], F_SETFL, O_NONBLOCK);

	for (i=0; i < ARRAY_SIZE(ipa_test_messages); i++)
		append_ipa_message(msg_out, 200, ipa_test_messages[i]);

	while (msg_out->len > 0) {
		int len = 5;
		if (len > msg_out->len)
			len = msg_out->len;
		if (write(sv[1], msg_out->data, len) == -1)
			err(1, "write");
		msgb_pull(msg_out, len);

		if (msg_out->len == 0)
			shutdown(sv[1], SHUT_WR);

		rc = receive_messages(sv[0],
				      do_not_assemble ? NULL : &pending_msg);

		if (rc == 0)
			break;

		if (rc < 0 && rc != -EAGAIN)
			break;
	}
	rc = slurp_data(sv[0]);
	printf("done: unread %d, unsent %d\n", rc, msg_out->len);

	close(sv[1]);
	close(sv[0]);

	msgb_free(msg_out);
	msgb_free(pending_msg);
}

static struct log_info info = {};

int main(int argc, char **argv)
{
	osmo_init_logging(&info);
	log_set_all_filter(osmo_stderr_target, 1);
	log_set_log_level(osmo_stderr_target, LOGL_INFO);

	printf("Testing the IPA layer.\n");

	/* run the tests */
	test_complete_recv(1);
	test_partial_recv(1);
	test_complete_recv(0);
	test_partial_recv(0);

	printf("No crashes.\n");
	return 0;
}
