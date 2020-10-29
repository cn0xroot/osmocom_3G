#include <osmocom/core/talloc.h>
#include <osmocom/core/msgb.h>
#include <osmocom/core/logging.h>
#include <osmocom/core/linuxlist.h>

#include <osmocom/netif/channel.h>

static LLIST_HEAD(channel_list);

extern struct osmo_chan_type chan_abis_ipa_srv;
extern struct osmo_chan_type chan_abis_ipa_cli;

static void *osmo_chan_ctx;

void osmo_chan_init(void *ctx)
{
	osmo_chan_ctx = ctx;
	llist_add(&chan_abis_ipa_srv.head, &channel_list);
	llist_add(&chan_abis_ipa_cli.head, &channel_list);
	/* add your new channel type here */
}

struct osmo_chan *osmo_chan_create(int type_id, int subtype_id)
{
	struct osmo_chan_type *cur = NULL;
	int found = 0, found_partial = 0;
	struct osmo_chan *c;

	if (type_id > OSMO_CHAN_MAX) {
		LOGP(DLINP, LOGL_ERROR, "unsupported channel type "
					"number `%u'\n", type_id);
		return NULL;
	}
	if (subtype_id > OSMO_SUBCHAN_MAX) {
		LOGP(DLINP, LOGL_ERROR, "unsupported subchannel type "
					"number `%u'\n", type_id);
		return NULL;
	}

	llist_for_each_entry(cur, &channel_list, head) {
		if (type_id == cur->type && subtype_id == cur->subtype) {
			found = 1;
			break;
		} else if (type_id == cur->type) {
			found_partial = 1;
			break;
		}
	}

	if (!found) {
		LOGP(DLINP, LOGL_ERROR, "unsupported channel type `%s'\n",
			cur->name);
		return NULL;
	}
	if (found_partial) {
		LOGP(DLINP, LOGL_ERROR, "Sorry, channel type `%s' does not "
			"support subtype `%u'\n", cur->name, subtype_id);
		return NULL;
	}

	c = talloc_zero_size(osmo_chan_ctx,
			     sizeof(struct osmo_chan) + cur->datasiz);
	if (c == NULL) {
		LOGP(DLINP, LOGL_ERROR, "cannot allocate channel data\n");
		return NULL;
	}

	c->ops = cur;

	if (c->ops->create(c) < 0) {
		LOGP(DLINP, LOGL_ERROR, "cannot create channel\n");
		talloc_free(c);
		return NULL;
	}
	return c;
}

void osmo_chan_destroy(struct osmo_chan *c)
{
	c->ops->destroy(c);
	talloc_free(c);
}

int osmo_chan_open(struct osmo_chan *c)
{
	return c->ops->open(c);
}

void osmo_chan_close(struct osmo_chan *c)
{
	c->ops->close(c);
}

int osmo_chan_enqueue(struct osmo_chan *c, struct msgb *msg)
{
	return c->ops->enqueue(c, msg);
}
