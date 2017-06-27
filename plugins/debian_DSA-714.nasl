#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Debian Security Advisory DSA-714. The text 
# itself is copyright (C) Software in the Public Interest, Inc.
#

include("compat.inc");

if (description)
{
  script_id(18143);
  script_version("$Revision: 1.15 $");
  script_cvs_date("$Date: 2013/05/18 00:15:58 $");

  script_cve_id("CVE-2005-1046");
  script_osvdb_id(15478);
  script_xref(name:"DSA", value:"714");

  script_name(english:"Debian DSA-714-1 : kdelibs - several vulnerabilities");
  script_summary(english:"Checks dpkg output for the updated package");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Debian host is missing a security-related update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"KDE security team discovered several vulnerabilities in the PCX and
other image file format readers in the KDE core libraries, some of
them exploitable to execute arbitrary code. To a small extent the
packages in woody are affected as well."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.debian.org/security/2005/dsa-714"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"Upgrade the kdelibs packages.

For the stable distribution (woody) this problem has been fixed in
version 2.2.2-13.woody.14."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:kdelibs");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:3.0");

  script_set_attribute(attribute:"patch_publication_date", value:"2005/04/26");
  script_set_attribute(attribute:"plugin_publication_date", value:"2005/04/27");
  script_set_attribute(attribute:"vuln_publication_date", value:"2005/03/24");
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
if (deb_check(release:"3.0", prefix:"kdelibs-dev", reference:"2.2.2-13.woody.14")) flag++;
if (deb_check(release:"3.0", prefix:"kdelibs3", reference:"2.2.2-13.woody.14")) flag++;
if (deb_check(release:"3.0", prefix:"kdelibs3-bin", reference:"2.2.2-13.woody.14")) flag++;
if (deb_check(release:"3.0", prefix:"kdelibs3-cups", reference:"2.2.2-13.woody.14")) flag++;
if (deb_check(release:"3.0", prefix:"kdelibs3-doc", reference:"2.2.2-13.woody.14")) flag++;
if (deb_check(release:"3.0", prefix:"libarts", reference:"2.2.2-13.woody.14")) flag++;
if (deb_check(release:"3.0", prefix:"libarts-alsa", reference:"2.2.2-13.woody.14")) flag++;
if (deb_check(release:"3.0", prefix:"libarts-dev", reference:"2.2.2-13.woody.14")) flag++;
if (deb_check(release:"3.0", prefix:"libkmid", reference:"2.2.2-13.woody.14")) flag++;
if (deb_check(release:"3.0", prefix:"libkmid-alsa", reference:"2.2.2-13.woody.14")) flag++;
if (deb_check(release:"3.0", prefix:"libkmid-dev", reference:"2.2.2-13.woody.14")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:deb_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
