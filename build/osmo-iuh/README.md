osmo-iuh - Osmocom Iuh and HNB-GW implementation
================================================

This repository contains a C-language implementation of the 3GPP Iuh
interface, together with a HNB-GW (Home NodeB Gateway).  You can use it
to interface Iuh-speaking femtocells/small cells to Iu-speaking MSCs and
SGSNs.

It is part of the [Osmocom](https://osmocom.org/) Open Source Mobile
Communications project.

Homepage
--------

The official homepage of the project is
https://osmocom.org/projects/osmohnbgw/wiki

GIT Repository
--------------

You can clone from the official libosmocore.git repository using

	git clone git://git.osmocom.org/osmo-iuh.git

There is a cgit interface at http://git.osmocom.org/osmo-iuh/

Documentation
-------------

There is currently no documentation beyond the wiki available on the
homepage.  We would love to see somebody contributing a manual that can
be part of the osmo-gsm-manuals suite.

Mailing List
------------

Discussions related to osmo-iuh are happening on the
openbsc@lists.osmocom.org mailing list, please see
https://lists.osmocom.org/mailman/listinfo/openbsc for subscription
options and the list archive.

Please observe the [Osmocom Mailing List
Rules](https://osmocom.org/projects/cellular-infrastructure/wiki/Mailing_List_Rules)
when posting.

Contributing
------------

Our coding standards are described at
https://osmocom.org/projects/cellular-infrastructure/wiki/Coding_standards

We us a gerrit based patch submission/review process for managing
contributions.  Please see
https://osmocom.org/projects/cellular-infrastructure/wiki/Gerrit for
more details

The current patch queue for osmo-iuh can be seen at
https://gerrit.osmocom.org/#/q/project:osmo-iuh+status:open


Building
--------

It is generally best to check the wiki for the most up-to-date build
instructions.

As external library dependencies, you will need
* libosmocore from git://git.osmocom.org/libosmocore
* libasn1c from git://git.osmocom.org/libasn1c
* libsctp-dev (this is the package name in Debian)
* libosmo-netif from git://git.osmocom.org/libosmo-netif (sysmocom/sctp branch)
* libosmo-sccp from git://git.osmocom.org/libosmo-sccp (sysmocom/iu branch)

To bootstrap the build, in the root directory, run:

    autoreconf --install

After that, run the usual

    ./configure [options]
    make
    [sudo] make install

Using
-----

Note: osmo-iuh just left very active development (December 2015, January
2016), so your mileage may vary.

If you run the 'hnbgw' executable, it will open a listening SCTP socket
and wait for incoming Iuh connections.  It will accept any
HNB-REGISTER-REQUEST, and it will establish Iu (over SUA) connections
towards the MSC and SGSN.

Regenerating C code from ASN.1 source
-------------------------------------

In order to re-generate the C source code from the ASN.1 source,
you will need a modified asn1c which has the following features:
* APER support (the patch from Eurecom, or its forward-ported version
  from the aper branch of git://git.osmocom.org/asn1c)
* support for prefixing the generated types (aper-prefix branch of
  git://git.osmocom.org/asn1c)
