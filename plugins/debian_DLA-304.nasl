#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Debian Security Advisory DLA-304-1. The text
# itself is copyright (C) Software in the Public Interest, Inc.
#

include("compat.inc");

if (description)
{
  script_id(85769);
  script_version("$Revision: 1.3 $");
  script_cvs_date("$Date: 2015/12/02 20:08:17 $");

  script_cve_id("CVE-2010-3609", "CVE-2012-4428", "CVE-2015-5177");
  script_bugtraq_id(46772, 55540);
  script_osvdb_id(85478, 126300);

  script_name(english:"Debian DLA-304-1 : openslp-dfsg security update");
  script_summary(english:"Checks dpkg output for the updated packages.");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Debian host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Several issues have been found and solved in OpenSLP, that implements
the Internet Engineering Task Force (IETF) Service Location Protocol
standards protocol.

CVE-2010-3609

Remote attackers could cause a Denial of Service in the Service
Location Protocol daemon (SLPD) via a crafted packet with a 'next
extension offset'.

CVE-2012-4428

Georgi Geshev discovered that an out-of-bounds read error in the
SLPIntersectStringList() function could be used to cause a DoS.

CVE-2015-5177

A double free in the SLPDProcessMessage() function could be used to
cause openslp to crash.

For Debian 6 'Squeeze', these problems have been fixed in openslp-dfsg
version 1.2.1-7.8+deb6u1.

We recommend that you upgrade your openslp-dfsg packages.

Learn more about the Debian Long Term Support (LTS) Project and how to
apply these updates at: https://wiki.debian.org/LTS/

NOTE: Tenable Network Security has extracted the preceding description
block directly from the DLA security advisory. Tenable has attempted
to automatically clean and format it as much as possible without
introducing additional issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://lists.debian.org/debian-lts-announce/2015/09/msg00000.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://packages.debian.org/source/squeeze-lts/openslp-dfsg"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://wiki.debian.org/LTS/"
  );
  script_set_attribute(attribute:"solution", value:"Upgrade the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:U/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libslp-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libslp1");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:openslp-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:slpd");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:slptool");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:6.0");

  script_set_attribute(attribute:"patch_publication_date", value:"2015/09/03");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/09/04");
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
if (deb_check(release:"6.0", prefix:"libslp-dev", reference:"1.2.1-7.8+deb6u1")) flag++;
if (deb_check(release:"6.0", prefix:"libslp1", reference:"1.2.1-7.8+deb6u1")) flag++;
if (deb_check(release:"6.0", prefix:"openslp-doc", reference:"1.2.1-7.8+deb6u1")) flag++;
if (deb_check(release:"6.0", prefix:"slpd", reference:"1.2.1-7.8+deb6u1")) flag++;
if (deb_check(release:"6.0", prefix:"slptool", reference:"1.2.1-7.8+deb6u1")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:deb_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
