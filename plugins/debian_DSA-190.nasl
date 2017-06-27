#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Debian Security Advisory DSA-190. The text 
# itself is copyright (C) Software in the Public Interest, Inc.
#

include("compat.inc");

if (description)
{
  script_id(15027);
  script_version("$Revision: 1.15 $");
  script_cvs_date("$Date: 2013/05/17 23:54:23 $");

  script_cve_id("CVE-2002-1277");
  script_osvdb_id(8356);
  script_xref(name:"DSA", value:"190");

  script_name(english:"Debian DSA-190-1 : wmaker - buffer overflow");
  script_summary(english:"Checks dpkg output for the updated package");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Debian host is missing a security-related update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Al Viro found a problem in the image handling code use in Window
Maker, a popular NEXTSTEP like window manager. When creating an image
it would allocate a buffer by multiplying the image width and height,
but did not check for an overflow. This makes it possible to overflow
the buffer. This could be exploited by using specially crafted image
files (for example when previewing themes)."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.debian.org/security/2002/dsa-190"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"This problem has been fixed in version 0.80.0-4.1 for the current
stable distribution (woody). Packages for the mipsel architecture are
not yet available."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:wmaker");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:3.0");

  script_set_attribute(attribute:"patch_publication_date", value:"2002/11/07");
  script_set_attribute(attribute:"plugin_publication_date", value:"2004/09/29");
  script_set_attribute(attribute:"vuln_publication_date", value:"2002/11/07");
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
if (deb_check(release:"3.0", prefix:"libwings-dev", reference:"0.80.0-4.1")) flag++;
if (deb_check(release:"3.0", prefix:"libwmaker0-dev", reference:"0.80.0-4.1")) flag++;
if (deb_check(release:"3.0", prefix:"libwraster2", reference:"0.80.0-4.1")) flag++;
if (deb_check(release:"3.0", prefix:"libwraster2-dev", reference:"0.80.0-4.1")) flag++;
if (deb_check(release:"3.0", prefix:"wmaker", reference:"0.80.0-4.1")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:deb_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
