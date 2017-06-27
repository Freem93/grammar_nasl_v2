#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Debian Security Advisory DLA-337-1. The text
# itself is copyright (C) Software in the Public Interest, Inc.
#

include("compat.inc");

if (description)
{
  script_id(86676);
  script_version("$Revision: 2.2 $");
  script_cvs_date("$Date: 2015/12/02 20:16:12 $");

  script_name(english:"Debian DLA-337-1 : busybox security update");
  script_summary(english:"Checks dpkg output for the updated packages.");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Debian host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"busybox, a collection of tiny utilities for small and embedded
systems, was vulnerable to crashing when handling a specially crafted
zip file. The issue was discovered by Gustavo Grieco.

For Debian 6 Squeeze, this issue has been fixed in busybox version
1.17.1-8+deb6u11.

NOTE: Tenable Network Security has extracted the preceding description
block directly from the DLA security advisory. Tenable has attempted
to automatically clean and format it as much as possible without
introducing additional issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://lists.debian.org/debian-lts-announce/2015/10/msg00016.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://packages.debian.org/source/squeeze-lts/busybox"
  );
  script_set_attribute(attribute:"solution", value:"Upgrade the affected packages.");
  script_set_attribute(attribute:"risk_factor", value:"High");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:busybox");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:busybox-static");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:busybox-syslogd");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:busybox-udeb");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:udhcpc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:udhcpd");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:6.0");

  script_set_attribute(attribute:"patch_publication_date", value:"2015/10/31");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/11/02");
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
if (deb_check(release:"6.0", prefix:"busybox", reference:"1:1.17.1-8+deb6u11")) flag++;
if (deb_check(release:"6.0", prefix:"busybox-static", reference:"1:1.17.1-8+deb6u11")) flag++;
if (deb_check(release:"6.0", prefix:"busybox-syslogd", reference:"1:1.17.1-8+deb6u11")) flag++;
if (deb_check(release:"6.0", prefix:"busybox-udeb", reference:"1:1.17.1-8+deb6u11")) flag++;
if (deb_check(release:"6.0", prefix:"udhcpc", reference:"1:1.17.1-8+deb6u11")) flag++;
if (deb_check(release:"6.0", prefix:"udhcpd", reference:"1:1.17.1-8+deb6u11")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:deb_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
