#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Debian Security Advisory DSA-1756. The text 
# itself is copyright (C) Software in the Public Interest, Inc.
#

include("compat.inc");

if (description)
{
  script_id(36066);
  script_version("$Revision: 1.15 $");
  script_cvs_date("$Date: 2015/03/19 14:28:19 $");

  script_cve_id("CVE-2009-1044", "CVE-2009-1169");
  script_bugtraq_id(34181, 34235);
  script_xref(name:"DSA", value:"1756");

  script_name(english:"Debian DSA-1756-1 : xulrunner - multiple vulnerabilities");
  script_summary(english:"Checks dpkg output for the updated package");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Debian host is missing a security-related update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Several remote vulnerabilities have been discovered in Xulrunner, a
runtime environment for XUL applications, such as the Iceweasel web
browser. The Common Vulnerabilities and Exposures project identifies
the following problems :

  - CVE-2009-1169
    Security researcher Guido Landi discovered that a XSL
    stylesheet could be used to crash the browser during a
    XSL transformation. An attacker could potentially use
    this crash to run arbitrary code on a victim's computer.

  - CVE-2009-1044
    Security researcher Nils reported via TippingPoint's
    Zero Day Initiative that the XUL tree method
    _moveToEdgeShift was in some cases triggering garbage
    collection routines on objects which were still in use.
    In such cases, the browser would crash when attempting
    to access a previously destroyed object and this crash
    could be used by an attacker to run arbitrary code on a
    victim's computer.

Note that after installing these updates, you will need to restart any
packages using xulrunner, typically iceweasel or epiphany.

As indicated in the Etch release notes, security support for the
Mozilla products in the oldstable distribution needed to be stopped
before the end of the regular Etch security maintenance life cycle.
You are strongly encouraged to upgrade to stable or switch to a still
supported browser."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2009-1169"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2009-1044"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.debian.org/security/2009/dsa-1756"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"Upgrade the xulrunner package.

For the stable distribution (lenny), these problems have been fixed in
version 1.9.0.7-0lenny2."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_cwe_id(399);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:xulrunner");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:5.0");

  script_set_attribute(attribute:"patch_publication_date", value:"2009/03/29");
  script_set_attribute(attribute:"plugin_publication_date", value:"2009/04/01");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2009-2015 Tenable Network Security, Inc.");
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
if (deb_check(release:"5.0", prefix:"libmozillainterfaces-java", reference:"1.9.0.7-0lenny2")) flag++;
if (deb_check(release:"5.0", prefix:"libmozjs-dev", reference:"1.9.0.7-0lenny2")) flag++;
if (deb_check(release:"5.0", prefix:"libmozjs1d", reference:"1.9.0.7-0lenny2")) flag++;
if (deb_check(release:"5.0", prefix:"libmozjs1d-dbg", reference:"1.9.0.7-0lenny2")) flag++;
if (deb_check(release:"5.0", prefix:"python-xpcom", reference:"1.9.0.7-0lenny2")) flag++;
if (deb_check(release:"5.0", prefix:"spidermonkey-bin", reference:"1.9.0.7-0lenny2")) flag++;
if (deb_check(release:"5.0", prefix:"xulrunner-1.9", reference:"1.9.0.7-0lenny2")) flag++;
if (deb_check(release:"5.0", prefix:"xulrunner-1.9-dbg", reference:"1.9.0.7-0lenny2")) flag++;
if (deb_check(release:"5.0", prefix:"xulrunner-1.9-gnome-support", reference:"1.9.0.7-0lenny2")) flag++;
if (deb_check(release:"5.0", prefix:"xulrunner-dev", reference:"1.9.0.7-0lenny2")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:deb_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
