#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Debian Security Advisory DLA-149-1. The text
# itself is copyright (C) Software in the Public Interest, Inc.
#

include("compat.inc");

if (description)
{
  script_id(82132);
  script_version("$Revision: 1.9 $");
  script_cvs_date("$Date: 2016/04/28 18:15:19 $");

  script_cve_id("CVE-2014-9297", "CVE-2014-9298");
  script_bugtraq_id(72583, 72584);
  script_osvdb_id(116071, 116072);
  script_xref(name:"TRA", value:"TRA-2015-04");

  script_name(english:"Debian DLA-149-1 : ntp security update");
  script_summary(english:"Checks dpkg output for the updated packages.");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Debian host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Several vulnerabilities were discovered in the ntp package, an
implementation of the Network Time Protocol. The Common
Vulnerabilities and Exposures project identifies the following
problems :

CVE-2014-9297

Stephen Roettger of the Google Security Team, Sebastian Krahmer of the
SUSE Security Team and Harlan Stenn of Network Time Foundation
discovered that the length value in extension fields is not properly
validated in several code paths in ntp_crypto.c, which could lead to
information leakage or denial of service (ntpd crash).

CVE-2014-9298

Stephen Roettger of the Google Security Team reported that ACLs based
on IPv6 ::1 addresses can be bypassed.

NOTE: Tenable Network Security has extracted the preceding description
block directly from the DLA security advisory. Tenable has attempted
to automatically clean and format it as much as possible without
introducing additional issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://lists.debian.org/debian-lts-announce/2015/02/msg00004.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://packages.debian.org/source/squeeze-lts/ntp"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.tenable.com/security/research/tra-2015-04"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Upgrade the affected ntp, ntp-doc, and ntpdate packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:ntp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:ntp-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:ntpdate");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:6.0");

  script_set_attribute(attribute:"patch_publication_date", value:"2015/02/07");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/03/26");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2015-2016 Tenable Network Security, Inc.");
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
if (deb_check(release:"6.0", prefix:"ntp", reference:"1:4.2.6.p2+dfsg-1+deb6u2")) flag++;
if (deb_check(release:"6.0", prefix:"ntp-doc", reference:"1:4.2.6.p2+dfsg-1+deb6u2")) flag++;
if (deb_check(release:"6.0", prefix:"ntpdate", reference:"1:4.2.6.p2+dfsg-1+deb6u2")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:deb_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
