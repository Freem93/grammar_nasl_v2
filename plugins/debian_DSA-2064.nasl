#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Debian Security Advisory DSA-2064. The text 
# itself is copyright (C) Software in the Public Interest, Inc.
#

include("compat.inc");

if (description)
{
  script_id(47153);
  script_version("$Revision: 1.13 $");
  script_cvs_date("$Date: 2014/05/22 11:11:53 $");

  script_cve_id("CVE-2010-0183", "CVE-2010-1196", "CVE-2010-1197", "CVE-2010-1198", "CVE-2010-1199", "CVE-2010-1200", "CVE-2010-1201", "CVE-2010-1202");
  script_bugtraq_id(41082, 41087, 41090, 41093, 41094, 41100, 41102, 41103);
  script_xref(name:"DSA", value:"2064");

  script_name(english:"Debian DSA-2064-1 : xulrunner - several vulnerabilities");
  script_summary(english:"Checks dpkg output for the updated package");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Debian host is missing a security-related update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Several remote vulnerabilities have been discovered in Xulrunner, a
runtime environment for XUL applications. The Common Vulnerabilities
and Exposures project identifies the following problems :

  - CVE-2010-0183
    'wushi' discovered that incorrect pointer handling in
    the frame processing code could lead to the execution of
    arbitrary code.

  - CVE-2010-1196
    'Nils' discovered that an integer overflow in DOM node
    parsing could lead to the execution of arbitrary code.

  - CVE-2010-1197
    Ilja von Sprundel discovered that incorrect parsing of
    Content-Disposition headers could lead to cross-site
    scripting.

  - CVE-2010-1198
    Microsoft engineers discovered that incorrect memory
    handling in the interaction of browser plugins could
    lead to the execution of arbitrary code.

  - CVE-2010-1199
    Martin Barbella discovered that an integer overflow in
    XSLT node parsing could lead to the execution of
    arbitrary code.

  - CVE-2010-1200
    Olli Pettay, Martijn Wargers, Justin Lebar, Jesse
    Ruderman, Ben Turner, Jonathan Kew and David Humphrey
    discovered crashes in the layout engine, which might
    allow the execution of arbitrary code.

  - CVE-2010-1201
    'boardraider' and 'stedenon' discovered crashes in the
    layout engine, which might allow the execution of
    arbitrary code.

  - CVE-2010-1202
    Bob Clary, Igor Bukanov, Gary Kwong and Andreas Gal
    discovered crashes in the JavaScript engine, which might
    allow the execution of arbitrary code."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2010-0183"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2010-1196"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2010-1197"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2010-1198"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2010-1199"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2010-1200"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2010-1201"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2010-1202"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.debian.org/security/2010/dsa-2064"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"Upgrade the xulrunner packages.

For the stable distribution (lenny), these problems have been fixed in
version 1.9.0.19-2."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:xulrunner");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:5.0");

  script_set_attribute(attribute:"patch_publication_date", value:"2010/06/27");
  script_set_attribute(attribute:"plugin_publication_date", value:"2010/06/29");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2010-2014 Tenable Network Security, Inc.");
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
if (deb_check(release:"5.0", prefix:"libmozillainterfaces-java", reference:"1.9.0.19-2")) flag++;
if (deb_check(release:"5.0", prefix:"libmozjs-dev", reference:"1.9.0.19-2")) flag++;
if (deb_check(release:"5.0", prefix:"libmozjs1d", reference:"1.9.0.19-2")) flag++;
if (deb_check(release:"5.0", prefix:"libmozjs1d-dbg", reference:"1.9.0.19-2")) flag++;
if (deb_check(release:"5.0", prefix:"python-xpcom", reference:"1.9.0.19-2")) flag++;
if (deb_check(release:"5.0", prefix:"spidermonkey-bin", reference:"1.9.0.19-2")) flag++;
if (deb_check(release:"5.0", prefix:"xulrunner-1.9", reference:"1.9.0.19-2")) flag++;
if (deb_check(release:"5.0", prefix:"xulrunner-1.9-dbg", reference:"1.9.0.19-2")) flag++;
if (deb_check(release:"5.0", prefix:"xulrunner-1.9-gnome-support", reference:"1.9.0.19-2")) flag++;
if (deb_check(release:"5.0", prefix:"xulrunner-dev", reference:"1.9.0.19-2")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:deb_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
