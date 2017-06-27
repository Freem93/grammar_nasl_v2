#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Debian Security Advisory DSA-1474. The text 
# itself is copyright (C) Software in the Public Interest, Inc.
#

include("compat.inc");

if (description)
{
  script_id(30066);
  script_version("$Revision: 1.10 $");
  script_cvs_date("$Date: 2013/05/17 23:45:45 $");

  script_cve_id("CVE-2007-6353");
  script_xref(name:"DSA", value:"1474");

  script_name(english:"Debian DSA-1474-1 : exiv2 - integer overflow");
  script_summary(english:"Checks dpkg output for the updated package");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Debian host is missing a security-related update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Meder Kydyraliev discovered an integer overflow in the thumbnail
handling of libexif, the EXIF/IPTC metadata manipulation library,
which could result in the execution of arbitrary code."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.debian.org/security/2008/dsa-1474"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"Upgrade the exiv2 packages.

The old stable distribution (sarge) doesn't contain exiv2 packages.

For the stable distribution (etch), this problem has been fixed in
version 0.10-1.5."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_cwe_id(189);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:exiv2");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:4.0");

  script_set_attribute(attribute:"patch_publication_date", value:"2008/01/23");
  script_set_attribute(attribute:"plugin_publication_date", value:"2008/01/27");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2008-2013 Tenable Network Security, Inc.");
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
if (deb_check(release:"4.0", prefix:"exiv2", reference:"0.10-1.5")) flag++;
if (deb_check(release:"4.0", prefix:"libexiv2-0.10", reference:"0.10-1.5")) flag++;
if (deb_check(release:"4.0", prefix:"libexiv2-dev", reference:"0.10-1.5")) flag++;
if (deb_check(release:"4.0", prefix:"libexiv2-doc", reference:"0.10-1.5")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:deb_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
