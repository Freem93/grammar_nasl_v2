#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Debian Security Advisory DSA-621. The text 
# itself is copyright (C) Software in the Public Interest, Inc.
#

include("compat.inc");

if (description)
{
  script_id(16074);
  script_version("$Revision: 1.15 $");
  script_cvs_date("$Date: 2013/05/18 00:15:57 $");

  script_cve_id("CVE-2004-1125");
  script_osvdb_id(12554);
  script_xref(name:"DSA", value:"621");

  script_name(english:"Debian DSA-621-1 : cupsys - buffer overflow");
  script_summary(english:"Checks dpkg output for the updated package");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Debian host is missing a security-related update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"An iDEFENSE security researcher discovered a buffer overflow in xpdf,
the Portable Document Format (PDF) suite. Similar code is present in
the PDF processing part of CUPS. A maliciously crafted PDF file could
exploit this problem, leading to the execution of arbitrary code."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://bugs.debian.org/cgi-bin/bugreport.cgi?bug=286988"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.debian.org/security/2004/dsa-621"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"Upgrade the cupsys packages.

For the stable distribution (woody) this problem has been fixed in
version 1.1.14-5woody11."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_cwe_id(20);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:cupsys");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:3.0");

  script_set_attribute(attribute:"patch_publication_date", value:"2004/12/31");
  script_set_attribute(attribute:"plugin_publication_date", value:"2005/01/02");
  script_set_attribute(attribute:"vuln_publication_date", value:"2004/12/21");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2005-2013 Tenable Network Security, Inc.");
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
if (deb_check(release:"3.0", prefix:"cupsys", reference:"1.1.14-5woody11")) flag++;
if (deb_check(release:"3.0", prefix:"cupsys-bsd", reference:"1.1.14-5woody11")) flag++;
if (deb_check(release:"3.0", prefix:"cupsys-client", reference:"1.1.14-5woody11")) flag++;
if (deb_check(release:"3.0", prefix:"cupsys-pstoraster", reference:"1.1.14-5woody11")) flag++;
if (deb_check(release:"3.0", prefix:"libcupsys2", reference:"1.1.14-5woody11")) flag++;
if (deb_check(release:"3.0", prefix:"libcupsys2-dev", reference:"1.1.14-5woody11")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:deb_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
