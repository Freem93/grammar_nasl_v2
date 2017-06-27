#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Debian Security Advisory DSA-2661. The text 
# itself is copyright (C) Software in the Public Interest, Inc.
#

include("compat.inc");

if (description)
{
  script_id(66004);
  script_version("$Revision: 1.4 $");
  script_cvs_date("$Date: 2015/02/16 15:37:40 $");

  script_cve_id("CVE-2013-1940");
  script_xref(name:"DSA", value:"2661");

  script_name(english:"Debian DSA-2661-1 : xorg-server - information disclosure");
  script_summary(english:"Checks dpkg output for the updated package");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Debian host is missing a security-related update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"David Airlie and Peter Hutterer of Red Hat discovered that
xorg-server, the X.Org X server was vulnerable to an information
disclosure flaw related to input handling and devices hotplug.

When an X server is running but not on front (for example because of a
VT switch), a newly plugged input device would still be recognized and
handled by the X server, which would actually transmit input events to
its clients on the background.

This could allow an attacker to recover some input events not intended
for the X clients, including sensitive information."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://packages.debian.org/source/squeeze/xorg-server"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.debian.org/security/2013/dsa-2661"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"Upgrade the xorg-server packages.

For the stable distribution (squeeze), this problem has been fixed in
version 2:1.7.7-16."
  );
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:P/I:N/A:N");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:xorg-server");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:6.0");

  script_set_attribute(attribute:"patch_publication_date", value:"2013/04/17");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/04/18");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2013-2015 Tenable Network Security, Inc.");
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
if (deb_check(release:"6.0", prefix:"xdmx", reference:"2:1.7.7-16")) flag++;
if (deb_check(release:"6.0", prefix:"xdmx-tools", reference:"2:1.7.7-16")) flag++;
if (deb_check(release:"6.0", prefix:"xnest", reference:"2:1.7.7-16")) flag++;
if (deb_check(release:"6.0", prefix:"xserver-common", reference:"2:1.7.7-16")) flag++;
if (deb_check(release:"6.0", prefix:"xserver-xephyr", reference:"2:1.7.7-16")) flag++;
if (deb_check(release:"6.0", prefix:"xserver-xfbdev", reference:"2:1.7.7-16")) flag++;
if (deb_check(release:"6.0", prefix:"xserver-xorg-core", reference:"2:1.7.7-16")) flag++;
if (deb_check(release:"6.0", prefix:"xserver-xorg-core-dbg", reference:"2:1.7.7-16")) flag++;
if (deb_check(release:"6.0", prefix:"xserver-xorg-core-udeb", reference:"2:1.7.7-16")) flag++;
if (deb_check(release:"6.0", prefix:"xserver-xorg-dev", reference:"2:1.7.7-16")) flag++;
if (deb_check(release:"6.0", prefix:"xvfb", reference:"2:1.7.7-16")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_note(port:0, extra:deb_report_get());
  else security_note(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
