#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Debian Security Advisory DLA-218-1. The text
# itself is copyright (C) Software in the Public Interest, Inc.
#

include("compat.inc");

if (description)
{
  script_id(83190);
  script_version("$Revision: 2.5 $");
  script_cvs_date("$Date: 2016/05/05 14:49:54 $");

  script_cve_id("CVE-2015-0255");
  script_bugtraq_id(72578);
  script_osvdb_id(118221);

  script_name(english:"Debian DLA-218-1 : xorg-server security update");
  script_summary(english:"Checks dpkg output for the updated packages.");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Debian host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Olivier Fourdan discovered that missing input validation in the
Xserver's handling of XkbSetGeometry requests may result in an
information leak or denial of service.

This upload to Debian squeeze-lts fixes the issue by not swapping
XkbSetGeometry data in the input buffer any more and checking strings'
length against request size.

NOTE: Tenable Network Security has extracted the preceding description
block directly from the DLA security advisory. Tenable has attempted
to automatically clean and format it as much as possible without
introducing additional issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://lists.debian.org/debian-lts-announce/2015/05/msg00001.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://packages.debian.org/source/squeeze-lts/xorg-server"
  );
  script_set_attribute(attribute:"solution", value:"Upgrade the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:xdmx");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:xdmx-tools");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:xnest");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:xserver-common");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:xserver-xephyr");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:xserver-xfbdev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:xserver-xorg-core");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:xserver-xorg-core-dbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:xserver-xorg-core-udeb");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:xserver-xorg-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:xvfb");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:6.0");

  script_set_attribute(attribute:"patch_publication_date", value:"2015/05/01");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/05/04");
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
if (deb_check(release:"6.0", prefix:"xdmx", reference:"2:1.7.7-18+deb6u2")) flag++;
if (deb_check(release:"6.0", prefix:"xdmx-tools", reference:"2:1.7.7-18+deb6u2")) flag++;
if (deb_check(release:"6.0", prefix:"xnest", reference:"2:1.7.7-18+deb6u2")) flag++;
if (deb_check(release:"6.0", prefix:"xserver-common", reference:"2:1.7.7-18+deb6u2")) flag++;
if (deb_check(release:"6.0", prefix:"xserver-xephyr", reference:"2:1.7.7-18+deb6u2")) flag++;
if (deb_check(release:"6.0", prefix:"xserver-xfbdev", reference:"2:1.7.7-18+deb6u2")) flag++;
if (deb_check(release:"6.0", prefix:"xserver-xorg-core", reference:"2:1.7.7-18+deb6u2")) flag++;
if (deb_check(release:"6.0", prefix:"xserver-xorg-core-dbg", reference:"2:1.7.7-18+deb6u2")) flag++;
if (deb_check(release:"6.0", prefix:"xserver-xorg-core-udeb", reference:"2:1.7.7-18+deb6u2")) flag++;
if (deb_check(release:"6.0", prefix:"xserver-xorg-dev", reference:"2:1.7.7-18+deb6u2")) flag++;
if (deb_check(release:"6.0", prefix:"xvfb", reference:"2:1.7.7-18+deb6u2")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:deb_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
