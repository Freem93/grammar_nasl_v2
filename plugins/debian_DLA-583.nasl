#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Debian Security Advisory DLA-583-1. The text
# itself is copyright (C) Software in the Public Interest, Inc.
#

include("compat.inc");

if (description)
{
  script_id(92705);
  script_version("$Revision: 2.2 $");
  script_cvs_date("$Date: 2016/12/06 20:03:52 $");

  script_cve_id("CVE-2016-1000212");
  script_osvdb_id(142215);

  script_name(english:"Debian DLA-583-1 : lighttpd security update");
  script_summary(english:"Checks dpkg output for the updated packages.");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Debian host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Dominic Scheirlinck and Scott Geary of Vend reported an insecure
behaviour in the lighttpd web server. Lighttpd assigned Proxy header
values from client requests to internal HTTP_PROXY environment
variables. This could be used to carry out Man in the Middle Attacks
(MIDM) or create connections to arbitrary hosts.

For Debian 7 'Wheezy', this issue has been fixed in version
1.4.31-4+deb7u5.

We recommend that you upgrade your lighttpd packages.

NOTE: Tenable Network Security has extracted the preceding description
block directly from the DLA security advisory. Tenable has attempted
to automatically clean and format it as much as possible without
introducing additional issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://lists.debian.org/debian-lts-announce/2016/08/msg00002.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://packages.debian.org/source/wheezy/lighttpd"
  );
  script_set_attribute(attribute:"solution", value:"Upgrade the affected packages.");
  script_set_attribute(attribute:"risk_factor", value:"High");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:lighttpd");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:lighttpd-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:lighttpd-mod-cml");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:lighttpd-mod-magnet");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:lighttpd-mod-mysql-vhost");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:lighttpd-mod-trigger-b4-dl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:lighttpd-mod-webdav");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:7.0");

  script_set_attribute(attribute:"patch_publication_date", value:"2016/08/03");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/08/04");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2016 Tenable Network Security, Inc.");
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
if (deb_check(release:"7.0", prefix:"lighttpd", reference:"1.4.31-4+deb7u5")) flag++;
if (deb_check(release:"7.0", prefix:"lighttpd-doc", reference:"1.4.31-4+deb7u5")) flag++;
if (deb_check(release:"7.0", prefix:"lighttpd-mod-cml", reference:"1.4.31-4+deb7u5")) flag++;
if (deb_check(release:"7.0", prefix:"lighttpd-mod-magnet", reference:"1.4.31-4+deb7u5")) flag++;
if (deb_check(release:"7.0", prefix:"lighttpd-mod-mysql-vhost", reference:"1.4.31-4+deb7u5")) flag++;
if (deb_check(release:"7.0", prefix:"lighttpd-mod-trigger-b4-dl", reference:"1.4.31-4+deb7u5")) flag++;
if (deb_check(release:"7.0", prefix:"lighttpd-mod-webdav", reference:"1.4.31-4+deb7u5")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:deb_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
