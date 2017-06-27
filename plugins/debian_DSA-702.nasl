#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Debian Security Advisory DSA-702. The text 
# itself is copyright (C) Software in the Public Interest, Inc.
#

include("compat.inc");

if (description)
{
  script_id(17673);
  script_version("$Revision: 1.17 $");
  script_cvs_date("$Date: 2013/05/18 00:15:58 $");

  script_cve_id("CVE-2005-0397", "CVE-2005-0759", "CVE-2005-0760", "CVE-2005-0762");
  script_bugtraq_id(12875);
  script_osvdb_id(14372, 15111, 15112, 15114);
  script_xref(name:"DSA", value:"702");

  script_name(english:"Debian DSA-702-1 : imagemagick - several vulnerabilities");
  script_summary(english:"Checks dpkg output for the updated package");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Debian host is missing a security-related update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Several vulnerabilities have been discovered in ImageMagick, a
commonly used image manipulation library. These problems can be
exploited by a carefully crafted graphic image. The Common
Vulnerabilities and Exposures project identifies the following
problems :

  - CAN-2005-0397
    Tavis Ormandy discovered a format string vulnerability
    in the filename handling code which allows a remote
    attacker to cause a denial of service and possibly
    execute arbitrary code.

  - CAN-2005-0759

    Andrei Nigmatulin discovered a denial of service
    condition which can be caused by an invalid tag in a
    TIFF image.

  - CAN-2005-0760

    Andrei Nigmatulin discovered that the TIFF decoder is
    vulnerable to accessing memory out of bounds which will
    result in a segmentation fault.

  - CAN-2005-0762

    Andrei Nigmatulin discovered a buffer overflow in the
    SGI parser which allows a remote attacker to execute
    arbitrary code via a specially crafted SGI image file."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://bugs.debian.org/cgi-bin/bugreport.cgi?bug=297990"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.debian.org/security/2005/dsa-702"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"Upgrade the imagemagick package.

For the stable distribution (woody) these problems have been fixed in
version 5.4.4.5-1woody6."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:imagemagick");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:3.0");

  script_set_attribute(attribute:"patch_publication_date", value:"2005/04/01");
  script_set_attribute(attribute:"plugin_publication_date", value:"2005/04/02");
  script_set_attribute(attribute:"vuln_publication_date", value:"2005/03/04");
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
if (deb_check(release:"3.0", prefix:"imagemagick", reference:"5.4.4.5-1woody6")) flag++;
if (deb_check(release:"3.0", prefix:"libmagick++5", reference:"5.4.4.5-1woody6")) flag++;
if (deb_check(release:"3.0", prefix:"libmagick++5-dev", reference:"5.4.4.5-1woody6")) flag++;
if (deb_check(release:"3.0", prefix:"libmagick5", reference:"5.4.4.5-1woody6")) flag++;
if (deb_check(release:"3.0", prefix:"libmagick5-dev", reference:"5.4.4.5-1woody6")) flag++;
if (deb_check(release:"3.0", prefix:"perlmagick", reference:"5.4.4.5-1woody6")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:deb_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
