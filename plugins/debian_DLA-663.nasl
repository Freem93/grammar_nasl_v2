#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Debian Security Advisory DLA-663-1. The text
# itself is copyright (C) Software in the Public Interest, Inc.
#

include("compat.inc");

if (description)
{
  script_id(94111);
  script_version("$Revision: 2.1 $");
  script_cvs_date("$Date: 2016/10/19 14:37:27 $");

  script_name(english:"Debian DLA-663-1 : tor security update");
  script_summary(english:"Checks dpkg output for the updated packages.");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Debian host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"It has been discovered that Tor treats the contents of some buffer
chunks as if they were a NUL-terminated string. This issue could
enable a remote attacker to crash a Tor client, hidden service, relay,
or authority. This update aims to defend against this general class of
security bugs.

For Debian 7 'Wheezy', this problem has been fixed in version
0.2.4.27-2.

For the stable distribution (jessie), this problem has been fixed in
version 0.2.5.12-3., for unstable (sid) with version 0.2.8.9-1, and
for experimental with 0.2.9.4-alpha-1.

Additionally, for wheezy this updates the set of authority directory
servers to the one from Tor 0.2.8.7, released in August 2016.

We recommend that you upgrade your tor packages.

NOTE: Tenable Network Security has extracted the preceding description
block directly from the DLA security advisory. Tenable has attempted
to automatically clean and format it as much as possible without
introducing additional issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://lists.debian.org/debian-lts-announce/2016/10/msg00019.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://packages.debian.org/source/wheezy/tor"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Upgrade the affected tor, tor-dbg, and tor-geoipdb packages."
  );
  script_set_attribute(attribute:"risk_factor", value:"High");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:tor");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:tor-dbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:tor-geoipdb");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:7.0");

  script_set_attribute(attribute:"patch_publication_date", value:"2016/10/18");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/10/19");
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
if (deb_check(release:"7.0", prefix:"tor", reference:"0.2.4.27-2")) flag++;
if (deb_check(release:"7.0", prefix:"tor-dbg", reference:"0.2.4.27-2")) flag++;
if (deb_check(release:"7.0", prefix:"tor-geoipdb", reference:"0.2.4.27-2")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:deb_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
