#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Debian Security Advisory DSA-222. The text 
# itself is copyright (C) Software in the Public Interest, Inc.
#

include("compat.inc");

if (description)
{
  script_id(15059);
  script_version("$Revision: 1.17 $");
  script_cvs_date("$Date: 2013/05/17 23:58:36 $");

  script_cve_id("CVE-2002-1384");
  script_bugtraq_id(6475);
  script_xref(name:"DSA", value:"222");

  script_name(english:"Debian DSA-222-1 : xpdf - integer overflow");
  script_summary(english:"Checks dpkg output for the updated package");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Debian host is missing a security-related update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"iDEFENSE discovered an integer overflow in the pdftops filter from the
xpdf package that can be exploited to gain the privileges of the
target user. This can lead to gaining unauthorized access to the 'lp'
user if the pdftops program is part of the print filter."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.idefense.com/advisory/12.23.02.txt"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.debian.org/security/2003/dsa-222"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"Upgrade the xpdf package.

For the current stable distribution (woody) this problem has been
fixed in version 1.00-3.1.

For the old stable distribution (potato) this problem has been fixed
in version 0.90-8.1."
  );
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:xpdf");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:2.2");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:3.0");

  script_set_attribute(attribute:"patch_publication_date", value:"2003/01/06");
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
if (deb_check(release:"2.2", prefix:"xpdf", reference:"0.90-8.1")) flag++;
if (deb_check(release:"3.0", prefix:"xpdf", reference:"1.00-3.1")) flag++;
if (deb_check(release:"3.0", prefix:"xpdf-common", reference:"1.00-3.1")) flag++;
if (deb_check(release:"3.0", prefix:"xpdf-reader", reference:"1.00-3.1")) flag++;
if (deb_check(release:"3.0", prefix:"xpdf-utils", reference:"1.00-3.1")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:deb_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
