#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Debian Security Advisory DSA-085. The text 
# itself is copyright (C) Software in the Public Interest, Inc.
#

include("compat.inc");

if (description)
{
  script_id(14922);
  script_version("$Revision: 1.15 $");
  script_cvs_date("$Date: 2013/05/17 23:36:50 $");

  script_cve_id("CVE-2001-1562");
  script_osvdb_id(20374);
  script_xref(name:"DSA", value:"085");

  script_name(english:"Debian DSA-085-1 : nvi - Format string vulnerability");
  script_summary(english:"Checks dpkg output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Debian host is missing a security-related update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Takeshi Uno found a very stupid format string vulnerability in all
 versions of nvi (in both, the plain and the multilingualized
 version). When a filename is saved, it ought to get displayed on the
 screen. The routine handling this didn't escape format strings."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.debian.org/security/2001/dsa-085"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"This problem has been fixed in version 1.79-16a.1 for nvi and
1.79+19991117-2.3 for nvi-m17n for the stable Debian GNU/Linux 2.2.

Even if we don't believe that this could lead into somebody gaining
access of another users account if they haven't lost their brain, we
recommend that you upgrade your nvi packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:nvi");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:nvi-m17n");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:2.2");

  script_set_attribute(attribute:"patch_publication_date", value:"2001/10/20");
  script_set_attribute(attribute:"plugin_publication_date", value:"2004/09/29");
  script_set_attribute(attribute:"vuln_publication_date", value:"2001/10/20");
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
if (deb_check(release:"2.2", prefix:"nvi", reference:"1.79-16a.1")) flag++;
if (deb_check(release:"2.2", prefix:"nvi-m17n", reference:"1.79+19991117-2.3")) flag++;
if (deb_check(release:"2.2", prefix:"nvi-m17n-canna", reference:"1.79+19991117-2.3")) flag++;
if (deb_check(release:"2.2", prefix:"nvi-m17n-common", reference:"1.79+19991117-2.3")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:deb_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
