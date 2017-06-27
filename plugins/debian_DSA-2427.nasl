#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Debian Security Advisory DSA-2427. The text 
# itself is copyright (C) Software in the Public Interest, Inc.
#

include("compat.inc");

if (description)
{
  script_id(58251);
  script_version("$Revision: 1.7 $");
  script_cvs_date("$Date: 2015/02/16 15:37:37 $");

  script_cve_id("CVE-2012-0247", "CVE-2012-0248");
  script_bugtraq_id(51957);
  script_osvdb_id(79003, 79004);
  script_xref(name:"DSA", value:"2427");

  script_name(english:"Debian DSA-2427-1 : imagemagick - several vulnerabilities");
  script_summary(english:"Checks dpkg output for the updated package");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Debian host is missing a security-related update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Two security vulnerabilities related to EXIF processing were
discovered in ImageMagick, a suite of programs to manipulate images.

  - CVE-2012-0247
    When parsing a maliciously crafted image with incorrect
    offset and count in the ResolutionUnit tag in EXIF IFD0,
    ImageMagick writes two bytes to an invalid address.

  - CVE-2012-0248
    Parsing a maliciously crafted image with an IFD whose
    all IOP tags value offsets point to the beginning of the
    IFD itself results in an endless loop and a denial of
    service."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2012-0247"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2012-0248"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://packages.debian.org/source/squeeze/imagemagick"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.debian.org/security/2012/dsa-2427"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"Upgrade the imagemagick packages.

For the stable distribution (squeeze), these problems have been fixed
in version 8:6.6.0.4-3+squeeze1."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:imagemagick");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:6.0");

  script_set_attribute(attribute:"patch_publication_date", value:"2012/03/06");
  script_set_attribute(attribute:"plugin_publication_date", value:"2012/03/07");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2012-2015 Tenable Network Security, Inc.");
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
if (deb_check(release:"6.0", prefix:"imagemagick", reference:"8:6.6.0.4-3+squeeze1")) flag++;
if (deb_check(release:"6.0", prefix:"imagemagick-dbg", reference:"8:6.6.0.4-3+squeeze1")) flag++;
if (deb_check(release:"6.0", prefix:"imagemagick-doc", reference:"8:6.6.0.4-3+squeeze1")) flag++;
if (deb_check(release:"6.0", prefix:"libmagick++-dev", reference:"8:6.6.0.4-3+squeeze1")) flag++;
if (deb_check(release:"6.0", prefix:"libmagick++3", reference:"8:6.6.0.4-3+squeeze1")) flag++;
if (deb_check(release:"6.0", prefix:"libmagickcore-dev", reference:"8:6.6.0.4-3+squeeze1")) flag++;
if (deb_check(release:"6.0", prefix:"libmagickcore3", reference:"8:6.6.0.4-3+squeeze1")) flag++;
if (deb_check(release:"6.0", prefix:"libmagickcore3-extra", reference:"8:6.6.0.4-3+squeeze1")) flag++;
if (deb_check(release:"6.0", prefix:"libmagickwand-dev", reference:"8:6.6.0.4-3+squeeze1")) flag++;
if (deb_check(release:"6.0", prefix:"libmagickwand3", reference:"8:6.6.0.4-3+squeeze1")) flag++;
if (deb_check(release:"6.0", prefix:"perlmagick", reference:"8:6.6.0.4-3+squeeze1")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:deb_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
