#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Debian Security Advisory DSA-3216. The text 
# itself is copyright (C) Software in the Public Interest, Inc.
#

include("compat.inc");

if (description)
{
  script_id(82624);
  script_version("$Revision: 1.1 $");
  script_cvs_date("$Date: 2015/04/08 13:41:02 $");

  script_cve_id("CVE-2015-2928", "CVE-2015-2929");
  script_xref(name:"DSA", value:"3216");

  script_name(english:"Debian DSA-3216-1 : tor - security update");
  script_summary(english:"Checks dpkg output for the updated package");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Debian host is missing a security-related update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Several vulnerabilities have been discovered in Tor, a
connection-based low-latency anonymous communication system :

  - CVE-2015-2928
    'disgleirio' discovered that a malicious client could
    trigger an assertion failure in a Tor instance providing
    a hidden service, thus rendering the service
    inaccessible.

  - CVE-2015-2929
    'DonnchaC' discovered that Tor clients would crash with
    an assertion failure upon parsing specially crafted
    hidden service descriptors.

Introduction points would accept multiple INTRODUCE1 cells on one
circuit, making it inexpensive for an attacker to overload a hidden
service with introductions. Introduction points now no longer allow
multiple cells of that type on the same circuit."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2015-2928"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2015-2929"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://packages.debian.org/source/wheezy/tor"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.debian.org/security/2015/dsa-3216"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"Upgrade the tor packages.

For the stable distribution (wheezy), these problems have been fixed
in version 0.2.4.27-1."
  );
  script_set_attribute(attribute:"risk_factor", value:"High");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:tor");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:7.0");

  script_set_attribute(attribute:"patch_publication_date", value:"2015/04/06");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/04/08");
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
if (deb_check(release:"7.0", prefix:"tor", reference:"0.2.4.27-1")) flag++;
if (deb_check(release:"7.0", prefix:"tor-dbg", reference:"0.2.4.27-1")) flag++;
if (deb_check(release:"7.0", prefix:"tor-geoipdb", reference:"0.2.4.27-1")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:deb_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
