#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Debian Security Advisory DSA-115. The text 
# itself is copyright (C) Software in the Public Interest, Inc.
#

include("compat.inc");

if (description)
{
  script_id(14952);
  script_version("$Revision: 1.18 $");
  script_cvs_date("$Date: 2013/05/17 23:41:26 $");

  script_cve_id("CVE-2002-0081");
  script_bugtraq_id(4183);
  script_osvdb_id(720, 34719);
  script_xref(name:"CERT", value:"297363");
  script_xref(name:"DSA", value:"115");

  script_name(english:"Debian DSA-115-1 : php - broken boundary check and more");
  script_summary(english:"Checks dpkg output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Debian host is missing a security-related update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Stefan Esser, who is also a member of the PHP team, found several
flawsin the way PHP handles multipart/form-data POST requests (as
described in RFC1867) known as POST fileuploads. Each of the flaws
could allow an attacker to execute arbitrary code on the victim's
system.

For PHP3 flaws contain a broken boundary check and an arbitrary heap
overflow. For PHP4 they consist of a broken boundary check and a heap
off by one error.

For the stable release of Debian these problems are fixed in version
3.0.18-0potato1.1 of PHP3 and version 4.0.3pl1-0potato3 of PHP4.

For the unstable and testing release of Debian these problems are
fixed in version 3.0.18-22 of PHP3 and version 4.1.2-1 of PHP4.

There is no PHP4 in the stable and unstable distribution for the arm
architecture due to a compiler error."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://security.e-matters.de/advisories/012002.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.debian.org/security/2002/dsa-115"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Upgrade the PHP packages immediately."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_core", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:php3");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:php4");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:2.2");

  script_set_attribute(attribute:"patch_publication_date", value:"2002/03/02");
  script_set_attribute(attribute:"plugin_publication_date", value:"2004/09/29");
  script_set_attribute(attribute:"vuln_publication_date", value:"2002/02/27");
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
if (deb_check(release:"2.2", prefix:"php3", reference:"3.0.18-0potato1.1")) flag++;
if (deb_check(release:"2.2", prefix:"php3-cgi", reference:"3.0.18-0potato1.1")) flag++;
if (deb_check(release:"2.2", prefix:"php3-cgi-gd", reference:"3.0.18-0potato1.1")) flag++;
if (deb_check(release:"2.2", prefix:"php3-cgi-imap", reference:"3.0.18-0potato1.1")) flag++;
if (deb_check(release:"2.2", prefix:"php3-cgi-ldap", reference:"3.0.18-0potato1.1")) flag++;
if (deb_check(release:"2.2", prefix:"php3-cgi-magick", reference:"3.0.18-0potato1.1")) flag++;
if (deb_check(release:"2.2", prefix:"php3-cgi-mhash", reference:"3.0.18-0potato1.1")) flag++;
if (deb_check(release:"2.2", prefix:"php3-cgi-mysql", reference:"3.0.18-0potato1.1")) flag++;
if (deb_check(release:"2.2", prefix:"php3-cgi-pgsql", reference:"3.0.18-0potato1.1")) flag++;
if (deb_check(release:"2.2", prefix:"php3-cgi-snmp", reference:"3.0.18-0potato1.1")) flag++;
if (deb_check(release:"2.2", prefix:"php3-cgi-xml", reference:"3.0.18-0potato1.1")) flag++;
if (deb_check(release:"2.2", prefix:"php3-dev", reference:"3.0.18-0potato1.1")) flag++;
if (deb_check(release:"2.2", prefix:"php3-doc", reference:"3.0.18-0potato1.1")) flag++;
if (deb_check(release:"2.2", prefix:"php3-gd", reference:"3.0.18-0potato1.1")) flag++;
if (deb_check(release:"2.2", prefix:"php3-imap", reference:"3.0.18-0potato1.1")) flag++;
if (deb_check(release:"2.2", prefix:"php3-ldap", reference:"3.0.18-0potato1.1")) flag++;
if (deb_check(release:"2.2", prefix:"php3-magick", reference:"3.0.18-0potato1.1")) flag++;
if (deb_check(release:"2.2", prefix:"php3-mhash", reference:"3.0.18-0potato1.1")) flag++;
if (deb_check(release:"2.2", prefix:"php3-mysql", reference:"3.0.18-0potato1.1")) flag++;
if (deb_check(release:"2.2", prefix:"php3-pgsql", reference:"3.0.18-0potato1.1")) flag++;
if (deb_check(release:"2.2", prefix:"php3-snmp", reference:"3.0.18-0potato1.1")) flag++;
if (deb_check(release:"2.2", prefix:"php3-xml", reference:"3.0.18-0potato1.1")) flag++;
if (deb_check(release:"2.2", prefix:"php4", reference:"4.0.3pl1-0potato3")) flag++;
if (deb_check(release:"2.2", prefix:"php4-cgi", reference:"4.0.3pl1-0potato3")) flag++;
if (deb_check(release:"2.2", prefix:"php4-cgi-gd", reference:"4.0.3pl1-0potato3")) flag++;
if (deb_check(release:"2.2", prefix:"php4-cgi-imap", reference:"4.0.3pl1-0potato3")) flag++;
if (deb_check(release:"2.2", prefix:"php4-cgi-ldap", reference:"4.0.3pl1-0potato3")) flag++;
if (deb_check(release:"2.2", prefix:"php4-cgi-mhash", reference:"4.0.3pl1-0potato3")) flag++;
if (deb_check(release:"2.2", prefix:"php4-cgi-mysql", reference:"4.0.3pl1-0potato3")) flag++;
if (deb_check(release:"2.2", prefix:"php4-cgi-pgsql", reference:"4.0.3pl1-0potato3")) flag++;
if (deb_check(release:"2.2", prefix:"php4-cgi-snmp", reference:"4.0.3pl1-0potato3")) flag++;
if (deb_check(release:"2.2", prefix:"php4-cgi-xml", reference:"4.0.3pl1-0potato3")) flag++;
if (deb_check(release:"2.2", prefix:"php4-dev", reference:"4.0.3pl1-0potato3")) flag++;
if (deb_check(release:"2.2", prefix:"php4-gd", reference:"4.0.3pl1-0potato3")) flag++;
if (deb_check(release:"2.2", prefix:"php4-imap", reference:"4.0.3pl1-0potato3")) flag++;
if (deb_check(release:"2.2", prefix:"php4-ldap", reference:"4.0.3pl1-0potato3")) flag++;
if (deb_check(release:"2.2", prefix:"php4-mhash", reference:"4.0.3pl1-0potato3")) flag++;
if (deb_check(release:"2.2", prefix:"php4-mysql", reference:"4.0.3pl1-0potato3")) flag++;
if (deb_check(release:"2.2", prefix:"php4-pgsql", reference:"4.0.3pl1-0potato3")) flag++;
if (deb_check(release:"2.2", prefix:"php4-snmp", reference:"4.0.3pl1-0potato3")) flag++;
if (deb_check(release:"2.2", prefix:"php4-xml", reference:"4.0.3pl1-0potato3")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:deb_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
