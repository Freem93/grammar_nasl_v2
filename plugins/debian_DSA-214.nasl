#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Debian Security Advisory DSA-214. The text 
# itself is copyright (C) Software in the Public Interest, Inc.
#

include("compat.inc");

if (description)
{
  script_id(15051);
  script_version("$Revision: 1.15 $");
  script_cvs_date("$Date: 2013/05/17 23:58:35 $");

  script_cve_id("CVE-2002-1306");
  script_xref(name:"DSA", value:"214");

  script_name(english:"Debian DSA-214-1 : kdenetwork - buffer overflows");
  script_summary(english:"Checks dpkg output for the updated package");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Debian host is missing a security-related update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Olaf Kirch from SuSE Linux AG discovered another vulnerability in the
klisa package, that provides a LAN information service similar to
'Network Neighbourhood'. The lisa daemon contains a buffer overflow
vulnerability which potentially enables any local user, as well as any
remote attacker on the LAN who is able to gain control of the LISa
port (7741 by default), to obtain root privileges. In addition, a
remote attacker potentially may be able to gain access to a victim's
account by using an 'rlan://' URL in an HTML page or via another KDE
application."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.debian.org/security/2002/dsa-214"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"Upgrade the klisa package immediately.

This problem has been fixed in version 2.2.2-14.5 for the current
stable distribution (woody) and in version 2.2.2-14.20 for the
unstable distribution (sid). The old stable distribution (potato) is
not affected since it doesn't contain a kdenetwork package."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:kdenetwork");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:3.0");

  script_set_attribute(attribute:"patch_publication_date", value:"2002/12/20");
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
if (deb_check(release:"3.0", prefix:"kdict", reference:"2.2.2-14.5")) flag++;
if (deb_check(release:"3.0", prefix:"kit", reference:"2.2.2-14.5")) flag++;
if (deb_check(release:"3.0", prefix:"klisa", reference:"2.2.2-14.5")) flag++;
if (deb_check(release:"3.0", prefix:"kmail", reference:"2.2.2-14.5")) flag++;
if (deb_check(release:"3.0", prefix:"knewsticker", reference:"2.2.2-14.5")) flag++;
if (deb_check(release:"3.0", prefix:"knode", reference:"2.2.2-14.5")) flag++;
if (deb_check(release:"3.0", prefix:"korn", reference:"2.2.2-14.5")) flag++;
if (deb_check(release:"3.0", prefix:"kppp", reference:"2.2.2-14.5")) flag++;
if (deb_check(release:"3.0", prefix:"ksirc", reference:"2.2.2-14.5")) flag++;
if (deb_check(release:"3.0", prefix:"ktalkd", reference:"2.2.2-14.5")) flag++;
if (deb_check(release:"3.0", prefix:"libkdenetwork1", reference:"2.2.2-14.5")) flag++;
if (deb_check(release:"3.0", prefix:"libmimelib-dev", reference:"2.2.2-14.5")) flag++;
if (deb_check(release:"3.0", prefix:"libmimelib1", reference:"2.2.2-14.5")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:deb_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
