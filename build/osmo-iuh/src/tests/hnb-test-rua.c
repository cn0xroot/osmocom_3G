
#include <asn1c/ANY.h>
#include <osmocom/rua/rua_ies_defs.h>

#include "hnb-test-layers.h"

void hnb_test_rua_dt_handle(struct hnb_test *hnb, ANY_t *in)
{
	RUA_DirectTransferIEs_t ies;
	int rc;

	rc = rua_decode_directtransferies(&ies, in);
	if (rc < 0) {
		printf("failed to decode RUA DT IEs\n");
		return;
	}

	rc = ranap_cn_rx_co(hnb_test_rua_dt_handle_ranap, hnb, ies.ranaP_Message.buf, ies.ranaP_Message.size);

	/* FIXME: what to do with the asn1c-allocated memory */
	rua_free_directtransferies(&ies);
}

void hnb_test_rua_cl_handle(struct hnb_test *hnb, ANY_t *in)
{
	RUA_ConnectionlessTransferIEs_t ies;
	int rc;

	rc = rua_decode_connectionlesstransferies(&ies, in);
	if (rc < 0) {
		printf("failed to decode RUA CL IEs\n");
		return;
	}

	rc = ranap_cn_rx_cl(hnb_test_rua_cl_handle_ranap, hnb, ies.ranaP_Message.buf, ies.ranaP_Message.size);

	/* FIXME: what to do with the asn1c-allocated memory */
	rua_free_connectionlesstransferies(&ies);
}

