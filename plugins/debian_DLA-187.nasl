#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Debian Security Advisory DLA-187-1. The text
# itself is copyright (C) Software in the Public Interest, Inc.
#

include("compat.inc");

if (description)
{
  script_id(82594);
  script_version("$Revision: 1.3 $");
  script_cvs_date("$Date: 2015/12/02 20:08:16 $");

  script_cve_id("CVE-2015-2928", "CVE-2015-2929");
  script_bugtraq_id(73932, 73938);

  script_name(english:"Debian DLA-187-1 : tor security update");
  script_summary(english:"Checks dpkg output for the updated packages.");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Debian host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Several hidden service related denial of service issues have been
discovered in Tor, a connection-based low-latency anonymous
communication system.

o 'disgleirio' discovered that a malicious client could trigger an
assertion failure in a Tor instance providing a hidden service, thus
rendering the service inaccessible. [CVE-2015-2928]

o 'DonnchaC' discovered that Tor clients would crash with an assertion
failure upon parsing specially crafted hidden service descriptors.
[CVE-2015-2929]

o Introduction points would accept multiple INTRODUCE1 cells on one
circuit, making it inexpensive for an attacker to overload a hidden
service with introductions. Introduction points no longer allow
multiple such cells on the same circuit.

NOTE: Tenable Network Security has extracted the preceding description
block directly from the DLA security advisory. Tenable has attempted
to automatically clean and format it as much as possible without
introducing additional issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://lists.debian.org/debian-lts-announce/2015/04/msg00001.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://packages.debian.org/source/squeeze-lts/tor"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Upgrade the affected tor, tor-dbg, and tor-geoipdb packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:tor");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:tor-dbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:tor-geoipdb");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:6.0");

  script_set_attribute(attribute:"patch_publication_date", value:"2015/04/06");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/04/07");
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
if (deb_check(release:"6.0", prefix:"tor", reference:"0.2.4.27-1~deb6u1")) flag++;
if (deb_check(release:"6.0", prefix:"tor-dbg", reference:"0.2.4.27-1~deb6u1")) flag++;
if (deb_check(release:"6.0", prefix:"tor-geoipdb", reference:"0.2.4.27-1~deb6u1")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:deb_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
