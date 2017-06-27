#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Debian Security Advisory DSA-1168. The text 
# itself is copyright (C) Software in the Public Interest, Inc.
#

include("compat.inc");

if (description)
{
  script_id(22710);
  script_version("$Revision: 1.12 $");
  script_cvs_date("$Date: 2016/05/26 15:53:37 $");

  script_cve_id("CVE-2006-2440", "CVE-2006-3743", "CVE-2006-3744");
  script_osvdb_id(28204, 28205, 28540);
  script_xref(name:"DSA", value:"1168");

  script_name(english:"Debian DSA-1168-1 : imagemagick - several vulnerabilities");
  script_summary(english:"Checks dpkg output for the updated package");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Debian host is missing a security-related update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Several remote vulnerabilities have been discovered in Imagemagick, a
collection of image manipulation tools, which may lead to the
execution of arbitrary code. The Common Vulnerabilities and Exposures
project identifies the following problems :

  - CVE-2006-2440
    Eero Hakkinen discovered that the display tool
    allocates insufficient memory for globbing patterns,
    which might lead to a buffer overflow.

  - CVE-2006-3743
    Tavis Ormandy from the Google Security Team discovered
    that the Sun bitmap decoder performs insufficient input
    sanitising, which might lead to buffer overflows and the
    execution of arbitrary code.

  - CVE-2006-3744
    Tavis Ormandy from the Google Security Team discovered
    that the XCF image decoder performs insufficient input
    sanitising, which might lead to buffer overflows and the
    execution of arbitrary code."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://bugs.debian.org/cgi-bin/bugreport.cgi?bug=345595"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2006-2440"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2006-3743"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2006-3744"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.debian.org/security/2006/dsa-1168"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"Upgrade the imagemagick packages.

For the stable distribution (sarge) these problems have been fixed in
version 6:6.0.6.2-2.7."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:imagemagick");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:3.1");

  script_set_attribute(attribute:"patch_publication_date", value:"2006/09/04");
  script_set_attribute(attribute:"plugin_publication_date", value:"2006/10/14");
  script_set_attribute(attribute:"vuln_publication_date", value:"2006/01/02");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2006-2016 Tenable Network Security, Inc.");
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
if (deb_check(release:"3.1", prefix:"imagemagick", reference:"6:6.0.6.2-2.7")) flag++;
if (deb_check(release:"3.1", prefix:"libmagick++6", reference:"6:6.0.6.2-2.7")) flag++;
if (deb_check(release:"3.1", prefix:"libmagick++6-dev", reference:"6:6.0.6.2-2.7")) flag++;
if (deb_check(release:"3.1", prefix:"libmagick6", reference:"6:6.0.6.2-2.7")) flag++;
if (deb_check(release:"3.1", prefix:"libmagick6-dev", reference:"6:6.0.6.2-2.7")) flag++;
if (deb_check(release:"3.1", prefix:"perlmagick", reference:"6:6.0.6.2-2.7")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:deb_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
