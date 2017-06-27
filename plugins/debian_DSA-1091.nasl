#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Debian Security Advisory DSA-1091. The text 
# itself is copyright (C) Software in the Public Interest, Inc.
#

include("compat.inc");

if (description)
{
  script_id(22633);
  script_version("$Revision: 1.13 $");
  script_cvs_date("$Date: 2014/05/03 11:14:57 $");

  script_cve_id("CVE-2006-2193", "CVE-2006-2656");
  script_osvdb_id(26030, 26031);
  script_xref(name:"DSA", value:"1091");

  script_name(english:"Debian DSA-1091-1 : tiff - buffer overflows");
  script_summary(english:"Checks dpkg output for the updated package");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Debian host is missing a security-related update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Several problems have been discovered in the TIFF library. The Common
Vulnerabilities and Exposures project identifies the following issues
:

  - CVE-2006-2193
    SuSE discovered a buffer overflow in the conversion of
    TIFF files into PDF documents which could be exploited
    when tiff2pdf is used e.g. in a printer filter.

  - CVE-2006-2656
    The tiffsplit command from the TIFF library contains a
    buffer overflow in the commandline handling which could
    be exploited when the program is executed automatically
    on unknown filenames."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://bugs.debian.org/cgi-bin/bugreport.cgi?bug=369819"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2006-2193"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2006-2656"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.debian.org/security/2006/dsa-1091"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"Upgrade the tiff packages.

For the old stable distribution (woody) this problem has been fixed in
version 3.5.5-7woody2.

For the stable distribution (sarge) this problem has been fixed in
version 3.7.2-5."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_cwe_id(119);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:tiff");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:3.0");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:3.1");

  script_set_attribute(attribute:"patch_publication_date", value:"2006/06/08");
  script_set_attribute(attribute:"plugin_publication_date", value:"2006/10/14");
  script_set_attribute(attribute:"vuln_publication_date", value:"2006/05/23");
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
if (deb_check(release:"3.0", prefix:"libtiff-tools", reference:"3.5.5-7woody2")) flag++;
if (deb_check(release:"3.0", prefix:"libtiff3g", reference:"3.5.5-7woody2")) flag++;
if (deb_check(release:"3.0", prefix:"libtiff3g-dev", reference:"3.5.5-7woody2")) flag++;
if (deb_check(release:"3.1", prefix:"libtiff-opengl", reference:"3.7.2-5")) flag++;
if (deb_check(release:"3.1", prefix:"libtiff-tools", reference:"3.7.2-5")) flag++;
if (deb_check(release:"3.1", prefix:"libtiff4", reference:"3.7.2-5")) flag++;
if (deb_check(release:"3.1", prefix:"libtiff4-dev", reference:"3.7.2-5")) flag++;
if (deb_check(release:"3.1", prefix:"libtiffxx0", reference:"3.7.2-5")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:deb_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
