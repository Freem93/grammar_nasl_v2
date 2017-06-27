#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Debian Security Advisory DSA-581. The text 
# itself is copyright (C) Software in the Public Interest, Inc.
#

include("compat.inc");

if (description)
{
  script_id(15679);
  script_version("$Revision: 1.15 $");
  script_cvs_date("$Date: 2013/05/18 00:11:36 $");

  script_cve_id("CVE-2004-0888");
  script_xref(name:"DSA", value:"581");

  script_name(english:"Debian DSA-581-1 : xpdf - integer overflows");
  script_summary(english:"Checks dpkg output for the updated package");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Debian host is missing a security-related update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Chris Evans discovered several integer overflows in xpdf, a viewer for
PDF files, which can be exploited remotely by a specially crafted PDF
document and lead to the execution of arbitrary code."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://bugs.debian.org/cgi-bin/bugreport.cgi?bug=278298"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.debian.org/security/2004/dsa-581"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"Upgrade the xpdf package.

For the stable distribution (woody) these problems have been fixed in
version 1.00-3.2."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:xpdf");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:3.0");

  script_set_attribute(attribute:"patch_publication_date", value:"2004/11/02");
  script_set_attribute(attribute:"plugin_publication_date", value:"2004/11/10");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2004-2013 Tenable Network Security, Inc.");
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
if (deb_check(release:"3.0", prefix:"xpdf", reference:"1.00-3.2")) flag++;
if (deb_check(release:"3.0", prefix:"xpdf-common", reference:"1.00-3.2")) flag++;
if (deb_check(release:"3.0", prefix:"xpdf-reader", reference:"1.00-3.2")) flag++;
if (deb_check(release:"3.0", prefix:"xpdf-utils", reference:"1.00-3.2")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:deb_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
