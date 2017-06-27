#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Debian Security Advisory DLA-120-2. The text
# itself is copyright (C) Software in the Public Interest, Inc.
#

include("compat.inc");

if (description)
{
  script_id(82103);
  script_version("$Revision: 1.8 $");
  script_cvs_date("$Date: 2016/12/21 14:22:36 $");

  script_cve_id("CVE-2014-8091", "CVE-2014-8092", "CVE-2014-8093", "CVE-2014-8094", "CVE-2014-8095", "CVE-2014-8096", "CVE-2014-8097", "CVE-2014-8098", "CVE-2014-8099", "CVE-2014-8100", "CVE-2014-8101", "CVE-2014-8102", "CVE-2015-3418");
  script_bugtraq_id(71595, 71596, 71597, 71598, 71599, 71600, 71601, 71602, 71604, 71605, 71606, 71608, 74328);
  script_osvdb_id(115603, 115604, 115605, 115606, 115607, 115608, 115609, 115610, 115611, 115612, 115613, 115615, 121282);

  script_name(english:"Debian DLA-120-2 : xorg-server regression update");
  script_summary(english:"Checks dpkg output for the updated packages.");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Debian host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Andreas Cord-Landwehr reported an issue where the X.Org Xserver would
often crash with an arithmetic exception when maximizing application
windows.

This issue (CVE-2015-3418) is a regression which got introduced by
fixing CVE-2014-8092. The above referenced version of xorg-server in
Debian squeeze-lts fixes this regression in the following way :

The length checking code validates PutImage height and byte width by
making sure that byte-width >= INT32_MAX / height. If height is zero,
this generates a divide by zero exception. Allow zero height requests
explicitly, bypassing the INT32_MAX check (in dix/dispatch.c).

NOTE: Tenable Network Security has extracted the preceding description
block directly from the DLA security advisory. Tenable has attempted
to automatically clean and format it as much as possible without
introducing additional issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://lists.debian.org/debian-lts-announce/2015/05/msg00002.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://packages.debian.org/source/squeeze-lts/xorg-server"
  );
  script_set_attribute(attribute:"solution", value:"Upgrade the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

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

  script_set_attribute(attribute:"patch_publication_date", value:"2015/05/03");
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
if (deb_check(release:"6.0", prefix:"xdmx", reference:"2:1.7.7-18+deb6u3")) flag++;
if (deb_check(release:"6.0", prefix:"xdmx-tools", reference:"2:1.7.7-18+deb6u3")) flag++;
if (deb_check(release:"6.0", prefix:"xnest", reference:"2:1.7.7-18+deb6u3")) flag++;
if (deb_check(release:"6.0", prefix:"xserver-common", reference:"2:1.7.7-18+deb6u3")) flag++;
if (deb_check(release:"6.0", prefix:"xserver-xephyr", reference:"2:1.7.7-18+deb6u3")) flag++;
if (deb_check(release:"6.0", prefix:"xserver-xfbdev", reference:"2:1.7.7-18+deb6u3")) flag++;
if (deb_check(release:"6.0", prefix:"xserver-xorg-core", reference:"2:1.7.7-18+deb6u3")) flag++;
if (deb_check(release:"6.0", prefix:"xserver-xorg-core-dbg", reference:"2:1.7.7-18+deb6u3")) flag++;
if (deb_check(release:"6.0", prefix:"xserver-xorg-core-udeb", reference:"2:1.7.7-18+deb6u3")) flag++;
if (deb_check(release:"6.0", prefix:"xserver-xorg-dev", reference:"2:1.7.7-18+deb6u3")) flag++;
if (deb_check(release:"6.0", prefix:"xvfb", reference:"2:1.7.7-18+deb6u3")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:deb_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
