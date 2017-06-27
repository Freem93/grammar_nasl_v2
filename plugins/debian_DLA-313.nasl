#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Debian Security Advisory DLA-313-1. The text
# itself is copyright (C) Software in the Public Interest, Inc.
#

include("compat.inc");

if (description)
{
  script_id(86195);
  script_version("$Revision: 2.2 $");
  script_cvs_date("$Date: 2015/12/02 20:08:18 $");

  script_cve_id("CVE-2013-3792", "CVE-2014-2486", "CVE-2014-2488", "CVE-2014-2489", "CVE-2015-2594");
  script_bugtraq_id(60794, 68610, 68618, 68621, 75899);
  script_osvdb_id(124728);

  script_name(english:"Debian DLA-313-1 : virtualbox-ose security update");
  script_summary(english:"Checks dpkg output for the updated packages.");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Debian host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"The latest maintenance release of the VirtualBox (OSE) 3.2.x series
(i.e., version 3.2.28) has been uploaded to Debian LTS (squeeze).
Thanks to Gianfranco Costamagna for preparing packages for review and
upload by the Debian LTS Team.

Unfortunately, Oracle no longer provides information on specific
security vulnerabilities in VirtualBox, thus we provide their latest
3.2.28 maintenance release in Debian LTS (squeeze) directly.

CVE-2013-3792

Oracle reported an unspecified vulnerability in the Oracle VM
VirtualBox component in Oracle Virtualization VirtualBox prior to
3.2.18, 4.0.20, 4.1.28, and 4.2.18 allows local users to affect
availability via unknown vectors related to Core.

The fix for CVE-2013-3792 prevents a virtio-net host DoS
vulnerability by adding large frame support to IntNet,
VirtioNet and NetFilter plus dropping oversized frames.

CVE-2014-2486

Unspecified vulnerability in the Oracle VM VirtualBox component in
Oracle Virtualization VirtualBox before 3.2.24, 4.0.26, 4.1.34,
4.2.26, and 4.3.12 allows local users to affect integrity and
availability via unknown vectors related to Core.

No further details have been provided, the attack range has
been given as local, severity low.

CVE-2014-2488

Unspecified vulnerability in the Oracle VM VirtualBox component in
Oracle Virtualization VirtualBox before 3.2.24, 4.0.26, 4.1.34,
4.2.26, and 4.3.12 allows local users to affect confidentiality via
unknown vectors related to Core.

No further details can been provided, the attack range has
been given as local, severity low.

CVE-2014-2489

Unspecified vulnerability in the Oracle VM VirtualBox component in
Oracle Virtualization VirtualBox before 3.2.24, 4.0.26, 4.1.34,
4.2.26, and 4.3.12 allows local users to affect confidentiality,
integrity, and availability via unknown vectors related to Core.

No further details can been provided, the attack range has
been given as local, severity medium.

CVE-2015-2594

Unspecified vulnerability in the Oracle VM VirtualBox component in
Oracle Virtualization VirtualBox prior to 4.0.32, 4.1.40, 4.2.32, and
4.3.30 allows local users to affect confidentiality, integrity, and
availability via unknown vectors related to Core.

This update fixes an issue related to guests using bridged
networking via WiFi.

NOTE: Tenable Network Security has extracted the preceding description
block directly from the DLA security advisory. Tenable has attempted
to automatically clean and format it as much as possible without
introducing additional issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://lists.debian.org/debian-lts-announce/2015/09/msg00013.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://packages.debian.org/source/squeeze-lts/virtualbox-ose"
  );
  script_set_attribute(attribute:"solution", value:"Upgrade the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:M/Au:S/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:virtualbox-ose");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:virtualbox-ose-dbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:virtualbox-ose-dkms");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:virtualbox-ose-fuse");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:virtualbox-ose-guest-dkms");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:virtualbox-ose-guest-source");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:virtualbox-ose-guest-utils");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:virtualbox-ose-guest-x11");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:virtualbox-ose-qt");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:virtualbox-ose-source");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:6.0");

  script_set_attribute(attribute:"patch_publication_date", value:"2015/09/29");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/09/30");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2015 Tenable Network Security, Inc.");
  script_family(english:"Debian Local Security Checks");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/Debian/release", "Host/Debian/dpkg-l");

  exit(0);
}


include("audit.inc");
include("debian_package.inc");


if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
if (!get_kb_item("Host/Debian/release")) audit(AUDIT_OS_NOT, "Debian");
if (!get_kb_item("Host/Debian/dpkg-l")) audit(AUDIT_PACKAGE_LIST_MISSING);


flag = 0;
if (deb_check(release:"6.0", prefix:"virtualbox-ose", reference:"3.2.28-dfsg-1+squeeze1")) flag++;
if (deb_check(release:"6.0", prefix:"virtualbox-ose-dbg", reference:"3.2.28-dfsg-1+squeeze1")) flag++;
if (deb_check(release:"6.0", prefix:"virtualbox-ose-dkms", reference:"3.2.28-dfsg-1+squeeze1")) flag++;
if (deb_check(release:"6.0", prefix:"virtualbox-ose-fuse", reference:"3.2.28-dfsg-1+squeeze1")) flag++;
if (deb_check(release:"6.0", prefix:"virtualbox-ose-guest-dkms", reference:"3.2.28-dfsg-1+squeeze1")) flag++;
if (deb_check(release:"6.0", prefix:"virtualbox-ose-guest-source", reference:"3.2.28-dfsg-1+squeeze1")) flag++;
if (deb_check(release:"6.0", prefix:"virtualbox-ose-guest-utils", reference:"3.2.28-dfsg-1+squeeze1")) flag++;
if (deb_check(release:"6.0", prefix:"virtualbox-ose-guest-x11", reference:"3.2.28-dfsg-1+squeeze1")) flag++;
if (deb_check(release:"6.0", prefix:"virtualbox-ose-qt", reference:"3.2.28-dfsg-1+squeeze1")) flag++;
if (deb_check(release:"6.0", prefix:"virtualbox-ose-source", reference:"3.2.28-dfsg-1+squeeze1")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:deb_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
