#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Debian Security Advisory DSA-1213. The text 
# itself is copyright (C) Software in the Public Interest, Inc.
#

include("compat.inc");

if (description)
{
  script_id(23662);
  script_version("$Revision: 1.13 $");
  script_cvs_date("$Date: 2014/05/03 11:14:58 $");

  script_cve_id("CVE-2006-0082", "CVE-2006-4144", "CVE-2006-5456", "CVE-2006-5868");
  script_osvdb_id(22671, 27951, 29989, 29990);
  script_xref(name:"DSA", value:"1213");

  script_name(english:"Debian DSA-1213-1 : imagemagick - several vulnerabilities");
  script_summary(english:"Checks dpkg output for the updated package");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Debian host is missing a security-related update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Several remote vulnerabilities have been discovered in Imagemagick, a
collection of image manipulation programs, which may lead to the
execution of arbitrary code. The Common Vulnerabilities and Exposures
project identifies the following problems :

  - CVE-2006-0082
    Daniel Kobras discovered that Imagemagick is vulnerable
    to format string attacks in the filename parsing code.

  - CVE-2006-4144
    Damian Put discovered that Imagemagick is vulnerable to
    buffer overflows in the module for SGI images.

  - CVE-2006-5456
    M Joonas Pihlaja discovered that Imagemagick is
    vulnerable to buffer overflows in the module for DCM and
    PALM images.

  - CVE-2006-5868
    Daniel Kobras discovered that Imagemagick is vulnerable
    to buffer overflows in the module for SGI images.

This update also addresses regressions in the XCF codec, which were
introduced in the previous security update."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://bugs.debian.org/cgi-bin/bugreport.cgi?bug=345876"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://bugs.debian.org/cgi-bin/bugreport.cgi?bug=383314"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://bugs.debian.org/cgi-bin/bugreport.cgi?bug=393025"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2006-0082"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2006-4144"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2006-5456"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2006-5868"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.debian.org/security/2006/dsa-1213"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"Upgrade the imagemagick packages.

For the stable distribution (sarge) these problems have been fixed in
version 6:6.0.6.2-2.8.

For the upcoming stable distribution (etch) these problems have been
fixed in version 7:6.2.4.5.dfsg1-0.11."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:imagemagick");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:3.1");

  script_set_attribute(attribute:"patch_publication_date", value:"2006/11/19");
  script_set_attribute(attribute:"plugin_publication_date", value:"2006/11/20");
  script_set_attribute(attribute:"vuln_publication_date", value:"2006/01/04");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2006-2014 Tenable Network Security, Inc.");
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
if (deb_check(release:"3.1", prefix:"imagemagick", reference:"6:6.0.6.2-2.8")) flag++;
if (deb_check(release:"3.1", prefix:"libmagick++6", reference:"6:6.0.6.2-2.8")) flag++;
if (deb_check(release:"3.1", prefix:"libmagick++6-dev", reference:"6:6.0.6.2-2.8")) flag++;
if (deb_check(release:"3.1", prefix:"libmagick6", reference:"6:6.0.6.2-2.8")) flag++;
if (deb_check(release:"3.1", prefix:"libmagick6-dev", reference:"6:6.0.6.2-2.8")) flag++;
if (deb_check(release:"3.1", prefix:"perlmagick", reference:"6:6.0.6.2-2.8")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:deb_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
