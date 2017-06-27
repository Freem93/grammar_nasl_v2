#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Debian Security Advisory DSA-1335. The text 
# itself is copyright (C) Software in the Public Interest, Inc.
#

include("compat.inc");

if (description)
{
  script_id(25744);
  script_version("$Revision: 1.14 $");
  script_cvs_date("$Date: 2014/05/03 11:14:58 $");

  script_cve_id("CVE-2006-4519", "CVE-2007-2949");
  script_osvdb_id(42139, 42140, 42141, 42142, 42143, 42144, 42145);
  script_xref(name:"DSA", value:"1335");

  script_name(english:"Debian DSA-1335-1 : gimp - several vulnerabilities");
  script_summary(english:"Checks dpkg output for the updated package");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Debian host is missing a security-related update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Several remote vulnerabilities have been discovered in Gimp, the GNU
Image Manipulation Program, which might lead to the execution of
arbitrary code. The Common Vulnerabilities and Exposures project
identifies the following problems :

  - CVE-2006-4519
    Sean Larsson discovered several integer overflows in the
    processing code for DICOM, PNM, PSD, RAS, XBM and XWD
    images, which might lead to the execution of arbitrary
    code if a user is tricked into opening such a malformed
    media file.

  - CVE-2007-2949
    Stefan Cornelius discovered an integer overflow in the
    processing code for PSD images, which might lead to the
    execution of arbitrary code if a user is tricked into
    opening such a malformed media file."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2006-4519"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2007-2949"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.debian.org/security/2007/dsa-1335"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"Upgrade the gimp packages.

For the oldstable distribution (sarge) these problems have been fixed
in version 2.2.6-1sarge4. Packages for mips and mipsel are not yet
available.

For the stable distribution (etch) these problems have been fixed in
version 2.2.13-1etch4. Packages for mips are not yet available."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_cwe_id(189);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:gimp");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:3.1");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:4.0");

  script_set_attribute(attribute:"patch_publication_date", value:"2007/07/18");
  script_set_attribute(attribute:"plugin_publication_date", value:"2007/07/23");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2007-2014 Tenable Network Security, Inc.");
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
if (deb_check(release:"3.1", prefix:"gimp", reference:"2.2.6-1sarge4")) flag++;
if (deb_check(release:"3.1", prefix:"gimp-data", reference:"2.2.6-1sarge4")) flag++;
if (deb_check(release:"3.1", prefix:"gimp-helpbrowser", reference:"2.2.6-1sarge4")) flag++;
if (deb_check(release:"3.1", prefix:"gimp-python", reference:"2.2.6-1sarge4")) flag++;
if (deb_check(release:"3.1", prefix:"gimp-svg", reference:"2.2.6-1sarge4")) flag++;
if (deb_check(release:"3.1", prefix:"gimp1.2", reference:"2.2.6-1sarge4")) flag++;
if (deb_check(release:"3.1", prefix:"libgimp2.0", reference:"2.2.6-1sarge4")) flag++;
if (deb_check(release:"3.1", prefix:"libgimp2.0-dev", reference:"2.2.6-1sarge4")) flag++;
if (deb_check(release:"3.1", prefix:"libgimp2.0-doc", reference:"2.2.6-1sarge4")) flag++;
if (deb_check(release:"4.0", prefix:"gimp", reference:"2.2.13-1etch4")) flag++;
if (deb_check(release:"4.0", prefix:"gimp-data", reference:"2.2.13-1etch4")) flag++;
if (deb_check(release:"4.0", prefix:"gimp-dbg", reference:"2.2.13-1etch4")) flag++;
if (deb_check(release:"4.0", prefix:"gimp-helpbrowser", reference:"2.2.13-1etch4")) flag++;
if (deb_check(release:"4.0", prefix:"gimp-python", reference:"2.2.13-1etch4")) flag++;
if (deb_check(release:"4.0", prefix:"gimp-svg", reference:"2.2.13-1etch4")) flag++;
if (deb_check(release:"4.0", prefix:"libgimp2.0", reference:"2.2.13-1etch4")) flag++;
if (deb_check(release:"4.0", prefix:"libgimp2.0-dev", reference:"2.2.13-1etch4")) flag++;
if (deb_check(release:"4.0", prefix:"libgimp2.0-doc", reference:"2.2.13-1etch4")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:deb_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
