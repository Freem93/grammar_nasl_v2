#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Debian Security Advisory DSA-074. The text 
# itself is copyright (C) Software in the Public Interest, Inc.
#

include("compat.inc");

if (description)
{
  script_id(14911);
  script_version("$Revision: 1.13 $");
  script_cvs_date("$Date: 2013/05/17 23:36:50 $");

  script_cve_id("CVE-2001-1027");
  script_xref(name:"DSA", value:"074");

  script_name(english:"Debian DSA-074-1 : wmaker - buffer overflow");
  script_summary(english:"Checks dpkg output for the updated package");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Debian host is missing a security-related update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Alban Hertroys found a buffer overflow in Window Maker (a popular
 window manager for X). The code that handles titles in the window
 list menu did not check the length of the title when copying it to a
 buffer. Since applications will set the title using data that can't
 be trusted (for example, most web browsers will include the title of
 the web page being shown in the title of their window), this could be
 exploited remotely."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.debian.org/security/2001/dsa-074"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"This has been fixed in version 0.61.1-4.1 of the Debian package, and
upstream version 0.65.1. We recommend that you update your Window
Maker package immediately."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:wmaker");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:2.2");

  script_set_attribute(attribute:"patch_publication_date", value:"2001/08/12");
  script_set_attribute(attribute:"plugin_publication_date", value:"2004/09/29");
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
if (deb_check(release:"2.2", prefix:"libdockapp-dev", reference:"0.61.1-4.1")) flag++;
if (deb_check(release:"2.2", prefix:"libwings-dev", reference:"0.61.1-4.1")) flag++;
if (deb_check(release:"2.2", prefix:"libwmaker0-dev", reference:"0.61.1-4.1")) flag++;
if (deb_check(release:"2.2", prefix:"libwraster1", reference:"0.61.1-4.1")) flag++;
if (deb_check(release:"2.2", prefix:"libwraster1-dev", reference:"0.61.1-4.1")) flag++;
if (deb_check(release:"2.2", prefix:"wmaker", reference:"0.61.1-4.1")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:deb_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
