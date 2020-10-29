
#ifndef UNIXSOCKET_PROTO_H
#define UNIXSOCKET_PROTO_H

/* The unix socket protocol is using a 2 byte header
 * containg the version and type.
 *
 * header: | 1b version | 1b type |
 *
 * for data packets it would be
 *
 * data:    | 0x1 | 0x0 | lapd ..|
 * control: | 0x1 | 0x1 | control payload |
 *
 * Atm there is only one control packet:
 *  - set_altc (superchannel or timeslot)
 *
 * set_altc payload:
 *  | 4b magic   | 1b new_state|
 *  | 0x23004200 | 0x0         | to timeslot
 *  | 0x23004200 | 0x1         | to superchannel
 */

#define UNIXSOCKET_PROTO_VERSION 0x1

enum {
	UNIXSOCKET_PROTO_DATA = 0x0,
	UNIXSOCKET_PROTO_CONTROL = 0x1,
};

#endif /* UNIXSOCKET_PROTO_H */
