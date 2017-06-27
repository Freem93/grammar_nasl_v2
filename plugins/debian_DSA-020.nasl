#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Debian Security Advisory DSA-020. The text 
# itself is copyright (C) Software in the Public Interest, Inc.
#

include("compat.inc");

if (description)
{
  script_id(14857);
  script_version("$Revision: 1.15 $");
  script_cvs_date("$Date: 2013/05/17 23:36:50 $");

  script_cve_id("CVE-2001-0108", "CVE-2001-1385");
  script_osvdb_id(5425);
  script_xref(name:"DSA", value:"020");

  script_name(english:"Debian DSA-020-1 : php4 - remote DOS and remote information leak");
  script_summary(english:"Checks dpkg output for the updated package");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Debian host is missing a security-related update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"The Zend people have found a vulnerability in older versions of PHP4
(the original advisory speaks of 4.0.4 while the bugs are present in
4.0.3 as well). It is possible to specify PHP directives on a
per-directory basis which leads to a remote attacker crafting an HTTP
request that would cause the next page to be served with the wrong
values for these directives. Also even if PHP is installed, it can be
activated and deactivated on a per-directory or per-virtual host basis
using the 'engine=on' or 'engine=off' directive. This setting can be
leaked to other virtual hosts on the same machine, effectively
disabling PHP for those hosts and resulting in PHP source code being
sent to the client instead of being executed on the server."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.debian.org/security/2001/dsa-020"
  );
  script_set_attribute(attribute:"solution", value:"Upgrade the affected php4 package.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:N");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:php4");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:2.2");

  script_set_attribute(attribute:"patch_publication_date", value:"2001/01/25");
  script_set_attribute(attribute:"plugin_publication_date", value:"2004/09/29");
  script_set_attribute(attribute:"vuln_publication_date", value:"2004/04/09");
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
if (deb_check(release:"2.2", prefix:"php4", reference:"4.0.3pl1-0potato1.1")) flag++;
if (deb_check(release:"2.2", prefix:"php4-cgi", reference:"4.0.3pl1-0potato1.1")) flag++;
if (deb_check(release:"2.2", prefix:"php4-cgi-gd", reference:"4.0.3pl1-0potato1.1")) flag++;
if (deb_check(release:"2.2", prefix:"php4-cgi-imap", reference:"4.0.3pl1-0potato1.1")) flag++;
if (deb_check(release:"2.2", prefix:"php4-cgi-ldap", reference:"4.0.3pl1-0potato1.1")) flag++;
if (deb_check(release:"2.2", prefix:"php4-cgi-mhash", reference:"4.0.3pl1-0potato1.1")) flag++;
if (deb_check(release:"2.2", prefix:"php4-cgi-mysql", reference:"4.0.3pl1-0potato1.1")) flag++;
if (deb_check(release:"2.2", prefix:"php4-cgi-pgsql", reference:"4.0.3pl1-0potato1.1")) flag++;
if (deb_check(release:"2.2", prefix:"php4-cgi-snmp", reference:"4.0.3pl1-0potato1.1")) flag++;
if (deb_check(release:"2.2", prefix:"php4-cgi-xml", reference:"4.0.3pl1-0potato1.1")) flag++;
if (deb_check(release:"2.2", prefix:"php4-gd", reference:"4.0.3pl1-0potato1.1")) flag++;
if (deb_check(release:"2.2", prefix:"php4-imap", reference:"4.0.3pl1-0potato1.1")) flag++;
if (deb_check(release:"2.2", prefix:"php4-ldap", reference:"4.0.3pl1-0potato1.1")) flag++;
if (deb_check(release:"2.2", prefix:"php4-mhash", reference:"4.0.3pl1-0potato1.1")) flag++;
if (deb_check(release:"2.2", prefix:"php4-mysql", reference:"4.0.3pl1-0potato1.1")) flag++;
if (deb_check(release:"2.2", prefix:"php4-pgsql", reference:"4.0.3pl1-0potato1.1")) flag++;
if (deb_check(release:"2.2", prefix:"php4-snmp", reference:"4.0.3pl1-0potato1.1")) flag++;
if (deb_check(release:"2.2", prefix:"php4-xml", reference:"4.0.3pl1-0potato1.1")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:deb_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
