#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Debian Security Advisory DLA-338-1. The text
# itself is copyright (C) Software in the Public Interest, Inc.
#

include("compat.inc");

if (description)
{
  script_id(86677);
  script_version("$Revision: 2.4 $");
  script_cvs_date("$Date: 2016/04/28 18:15:20 $");

  script_cve_id("CVE-2015-8025");
  script_osvdb_id(129445);

  script_name(english:"Debian DLA-338-1 : xscreensaver security update");
  script_summary(english:"Checks dpkg output for the updated packages.");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Debian host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"xscreensaver, a screensaver daemon and frontend for X11 was vulnerable
to crashing when hot-swapping monitors.

For Debian 6 Squeeze, this issue has been fixed in xscreensaver
version 5.11-1+deb6u11.

NOTE: Tenable Network Security has extracted the preceding description
block directly from the DLA security advisory. Tenable has attempted
to automatically clean and format it as much as possible without
introducing additional issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://lists.debian.org/debian-lts-announce/2015/10/msg00017.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://packages.debian.org/source/squeeze-lts/xscreensaver"
  );
  script_set_attribute(attribute:"solution", value:"Upgrade the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:N/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:xscreensaver");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:xscreensaver-data");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:xscreensaver-data-extra");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:xscreensaver-gl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:xscreensaver-gl-extra");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:xscreensaver-screensaver-bsod");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:xscreensaver-screensaver-webcollage");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:6.0");

  script_set_attribute(attribute:"patch_publication_date", value:"2015/10/31");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/11/02");
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
if (deb_check(release:"6.0", prefix:"xscreensaver", reference:"5.11-1+deb6u11")) flag++;
if (deb_check(release:"6.0", prefix:"xscreensaver-data", reference:"5.11-1+deb6u11")) flag++;
if (deb_check(release:"6.0", prefix:"xscreensaver-data-extra", reference:"5.11-1+deb6u11")) flag++;
if (deb_check(release:"6.0", prefix:"xscreensaver-gl", reference:"5.11-1+deb6u11")) flag++;
if (deb_check(release:"6.0", prefix:"xscreensaver-gl-extra", reference:"5.11-1+deb6u11")) flag++;
if (deb_check(release:"6.0", prefix:"xscreensaver-screensaver-bsod", reference:"5.11-1+deb6u11")) flag++;
if (deb_check(release:"6.0", prefix:"xscreensaver-screensaver-webcollage", reference:"5.11-1+deb6u11")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_note(port:0, extra:deb_report_get());
  else security_note(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
