libsmpp34 - C library for SMPP 3.4
==================================

This repository contains a C-language library implementing the SMPP
Protocol version 3.4 as specified by the SMPP Developers Forum.

The library was inherited from the
[c-open-smmp34](https://sourceforge.net/projects/c-open-smpp-34/)
project, which unfortunately doesn't have any form of revision control
system and hence the [Osmocom](https://osmocom.org/) Open Source
Mobile Communications project has imported the v1.10 release into this
git repository and performed subsequent improvements.

Homepage
--------

The official homepage of the Osmocom version of the library is
<http://osmocom.org/projects/libsmpp34>
while the original upstream project is found at
<https://sourceforge.net/projects/c-open-smpp-34/>

GIT Repository
--------------

You can clone from the Osmocom libsmpp34.git repository using

	git clone git://git.osmocom.org/libsmpp34.git

There is a cgit interface at <http://git.osmocom.org/libsmpp34/>

Documentation
-------------

API documentation is generated during the build
process, but also available online from the upstream project at
<http://c-open-smpp-34.sourceforge.net/out-1.10/web/c-open-libsmpp34_en/index.html>

Mailing List
------------

Discussions related to libsmpp34 are happening on the
openbsc@lists.osmocom.org mailing list, please see
https://lists.osmocom.org/mailman/listinfo/openbsc for subscription
options and the list archive.

Please observe the [Osmocom Mailing List
Rules](https://osmocom.org/projects/cellular-infrastructure/wiki/Mailing_List_Rules)
when posting.

Contributing
------------

Our coding standards are described at
<https://osmocom.org/projects/cellular-infrastructure/wiki/Coding_standards>

We us a gerrit based patch submission/review process for managing
contributions.  Please see
<https://osmocom.org/projects/cellular-infrastructure/wiki/Gerrit> for
more details

The current patch queue for libosmocore can be seen at
<https://gerrit.osmocom.org/#/q/project:libsmpp34+status:open>
