#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Debian Security Advisory DLA-178-1. The text
# itself is copyright (C) Software in the Public Interest, Inc.
#

include("compat.inc");

if (description)
{
  script_id(82163);
  script_version("$Revision: 1.2 $");
  script_cvs_date("$Date: 2015/12/02 20:08:16 $");

  script_name(english:"Debian DLA-178-1 : tor security update");
  script_summary(english:"Checks dpkg output for the updated packages.");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Debian host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Several issues have been discovered and fixed in Tor, a
connection-based low-latency anonymous communication system.

o Jowr discovered that very high DNS query load on a relay could
trigger an assertion error.

o A relay could crash with an assertion error if a buffer of
exactly the wrong layout was passed to buf_pullup() at
exactly the wrong time.

o When sending the address of the chosen rendezvous point to
a hidden service clients were leaking to the hidden service
they were on a little-endian or big-endian systems.

Furthermore, this update disables support for SSLv3 in Tor. All
versions of OpenSSL in use with Tor today support TLS 1.0 or later.

Additionally, this release updates the geoIP database used by Tor as
well as the list of directory authority servers, which Tor clients use
to bootstrap and trust to sign the Tor directory consensus document.

NOTE: Tenable Network Security has extracted the preceding description
block directly from the DLA security advisory. Tenable has attempted
to automatically clean and format it as much as possible without
introducing additional issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://lists.debian.org/debian-lts-announce/2015/03/msg00015.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://packages.debian.org/source/squeeze-lts/tor"
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
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:6.0");

  script_set_attribute(attribute:"patch_publication_date", value:"2015/03/22");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/03/26");
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
if (deb_check(release:"6.0", prefix:"tor", reference:"0.2.4.26-1~deb6u1")) flag++;
if (deb_check(release:"6.0", prefix:"tor-dbg", reference:"0.2.4.26-1~deb6u1")) flag++;
if (deb_check(release:"6.0", prefix:"tor-geoipdb", reference:"0.2.4.26-1~deb6u1")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:deb_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
