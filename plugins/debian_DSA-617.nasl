#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Debian Security Advisory DSA-617. The text 
# itself is copyright (C) Software in the Public Interest, Inc.
#

include("compat.inc");

if (description)
{
  script_id(16048);
  script_version("$Revision: 1.16 $");
  script_cvs_date("$Date: 2013/05/18 00:15:57 $");

  script_cve_id("CVE-2004-1307", "CVE-2004-1308");
  script_osvdb_id(12555, 12556);
  script_xref(name:"DSA", value:"617");

  script_name(english:"Debian DSA-617-1 : tiff - insufficient input validation");
  script_summary(english:"Checks dpkg output for the updated package");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Debian host is missing a security-related update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"'infamous41md' discovered a problem in libtiff, the Tag Image File
Format library for processing TIFF graphics files. Upon reading a TIFF
file it is possible to allocate a zero sized buffer and write to it
which would lead to the execution of arbitrary code."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.debian.org/security/2004/dsa-617"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"Upgrade the libtiff packages immediately.

For the stable distribution (woody) this problem has been fixed in
version 3.5.5-6.woody3."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:tiff");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:3.0");

  script_set_attribute(attribute:"patch_publication_date", value:"2004/12/24");
  script_set_attribute(attribute:"plugin_publication_date", value:"2004/12/27");
  script_set_attribute(attribute:"vuln_publication_date", value:"2004/12/21");
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
if (deb_check(release:"3.0", prefix:"libtiff-tools", reference:"3.5.5-6.woody3")) flag++;
if (deb_check(release:"3.0", prefix:"libtiff3g", reference:"3.5.5-6.woody3")) flag++;
if (deb_check(release:"3.0", prefix:"libtiff3g-dev", reference:"3.5.5-6.woody3")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:deb_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
