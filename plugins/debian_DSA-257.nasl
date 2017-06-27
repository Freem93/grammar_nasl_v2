#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Debian Security Advisory DSA-257. The text 
# itself is copyright (C) Software in the Public Interest, Inc.
#

include("compat.inc");

if (description)
{
  script_id(15094);
  script_version("$Revision: 1.21 $");
  script_cvs_date("$Date: 2017/04/27 13:33:46 $");

  script_cve_id("CVE-2002-1337");
  script_xref(name:"CERT", value:"398025");
  script_xref(name:"DSA", value:"257");

  script_name(english:"Debian DSA-257-1 : sendmail - remote exploit");
  script_summary(english:"Checks dpkg output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Debian host is missing a security-related update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Mark Dowd of ISS X-Force found a bug in the header parsing routines of
sendmail: it could overflow a buffer overflow when encountering
addresses with very long comments. Since sendmail also parses headers
when forwarding emails this vulnerability can hit mail-servers which
do not deliver the email as well."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.debian.org/security/2003/dsa-257"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"This has been fixed in upstream release 8.12.8, version 8.12.3-5 of
the package for Debian GNU/Linux 3.0/woody and version 8.9.3-25 of the
package for Debian GNU/Linux 2.2/potato.

DSA-257-2: Updated sendmail-wide packages are available in package
version 8.9.3+3.2W-24 for Debian 2.2 (potato) and version
8.12.3+3.5Wbeta-5.2 for Debian 3.0 (woody)."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:sendmail");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:sendmail-wide");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:2.2");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:3.0");

  script_set_attribute(attribute:"patch_publication_date", value:"2003/03/04");
  script_set_attribute(attribute:"plugin_publication_date", value:"2004/09/29");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2004-2017 Tenable Network Security, Inc.");
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
if (deb_check(release:"2.2", prefix:"sendmail", reference:"8.9.3-25")) flag++;
if (deb_check(release:"2.2", prefix:"sendmail-wide", reference:"8.9.3+3.2W-24")) flag++;
if (deb_check(release:"3.0", prefix:"libmilter-dev", reference:"8.12.3-5")) flag++;
if (deb_check(release:"3.0", prefix:"sendmail", reference:"8.12.3-5")) flag++;
if (deb_check(release:"3.0", prefix:"sendmail-doc", reference:"8.12.3-5")) flag++;
if (deb_check(release:"3.0", prefix:"sendmail-wide", reference:"8.12.3+3.5Wbeta-5.2")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:deb_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
