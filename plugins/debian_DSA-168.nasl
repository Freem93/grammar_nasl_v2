#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Debian Security Advisory DSA-168. The text 
# itself is copyright (C) Software in the Public Interest, Inc.
#

include("compat.inc");

if (description)
{
  script_id(15005);
  script_version("$Revision: 1.23 $");
  script_cvs_date("$Date: 2016/05/26 15:53:37 $");

  script_cve_id("CVE-2002-0985", "CVE-2002-0986", "CVE-2002-1783");
  script_bugtraq_id(5681);
  script_osvdb_id(2111, 2160, 59760);
  script_xref(name:"DSA", value:"168");

  script_name(english:"Debian DSA-168-1 : php - bypassing safe_mode, CRLF injection");
  script_summary(english:"Checks dpkg output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Debian host is missing a security-related update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Wojciech Purczynski found out that it is possible for scripts to pass
arbitrary text to sendmail as commandline extension when sending a
mail through PHP even when safe_mode is turned on. Passing 5th
argument should be disabled if PHP is configured in safe_mode, which
is the case for newer PHP versions and for the versions below. This
does not affect PHP3, though.

Wojciech Purczynski also found out that arbitrary ASCII control
characters may be injected into string arguments of the mail()
function. If mail() arguments are taken from user's input it may give
the user ability to alter message content including mail headers.

Ulf Harnhammar discovered that file() and fopen() are vulnerable to
CRLF injection. An attacker could use it to escape certain
restrictions and add arbitrary text to alleged HTTP requests that are
passed through.

However this only happens if something is passed to these functions
which is neither a valid file name nor a valid url. Any string that
contains control chars cannot be a valid url. Before you pass a string
that should be a url to any function you must use urlencode() to
encode it.

Three problems have been identified in PHP :

  - The mail() function can allow arbitrary email headers to
    be specified if a recipient address or subject contains
    CR/LF characters.
  - The mail() function does not properly disable the
    passing of arbitrary command-line options to sendmail
    when running in Safe Mode.

  - The fopen() function, when retrieving a URL, can allow
    manipulation of the request for the resource through a
    URL containing CR/LF characters. For example, headers
    could be added to an HTTP request.

These problems have been fixed in version 3.0.18-23.1woody1 for PHP3
and 4.1.2-5 for PHP4 for the current stable distribution (woody), in
version 3.0.18-0potato1.2 for PHP3 and 4.0.3pl1-0potato4 for PHP4 in
the old stable distribution (potato) and in version 3.0.18-23.2 for
PHP3 and 4.2.3-3 for PHP4 for the unstable distribution (sid)."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.debian.org/security/2002/dsa-168"
  );
  script_set_attribute(attribute:"solution", value:"Upgrade the PHP packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:H/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No exploit is required");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:PHP3");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:PHP4");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:2.2");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:3.0");

  script_set_attribute(attribute:"patch_publication_date", value:"2002/09/18");
  script_set_attribute(attribute:"plugin_publication_date", value:"2004/09/29");
  script_set_attribute(attribute:"vuln_publication_date", value:"2003/07/30");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2004-2016 Tenable Network Security, Inc.");
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
if (deb_check(release:"2.2", prefix:"php3", reference:"3.0.18-0potato1.2")) flag++;
if (deb_check(release:"2.2", prefix:"php3-cgi", reference:"3.0.18-0potato1.2")) flag++;
if (deb_check(release:"2.2", prefix:"php3-cgi-gd", reference:"3.0.18-0potato1.2")) flag++;
if (deb_check(release:"2.2", prefix:"php3-cgi-imap", reference:"3.0.18-0potato1.2")) flag++;
if (deb_check(release:"2.2", prefix:"php3-cgi-ldap", reference:"3.0.18-0potato1.2")) flag++;
if (deb_check(release:"2.2", prefix:"php3-cgi-magick", reference:"3.0.18-0potato1.2")) flag++;
if (deb_check(release:"2.2", prefix:"php3-cgi-mhash", reference:"3.0.18-0potato1.2")) flag++;
if (deb_check(release:"2.2", prefix:"php3-cgi-mysql", reference:"3.0.18-0potato1.2")) flag++;
if (deb_check(release:"2.2", prefix:"php3-cgi-pgsql", reference:"3.0.18-0potato1.2")) flag++;
if (deb_check(release:"2.2", prefix:"php3-cgi-snmp", reference:"3.0.18-0potato1.2")) flag++;
if (deb_check(release:"2.2", prefix:"php3-cgi-xml", reference:"3.0.18-0potato1.2")) flag++;
if (deb_check(release:"2.2", prefix:"php3-dev", reference:"3.0.18-0potato1.2")) flag++;
if (deb_check(release:"2.2", prefix:"php3-doc", reference:"3.0.18-0potato1.2")) flag++;
if (deb_check(release:"2.2", prefix:"php3-gd", reference:"3.0.18-0potato1.2")) flag++;
if (deb_check(release:"2.2", prefix:"php3-imap", reference:"3.0.18-0potato1.2")) flag++;
if (deb_check(release:"2.2", prefix:"php3-ldap", reference:"3.0.18-0potato1.2")) flag++;
if (deb_check(release:"2.2", prefix:"php3-magick", reference:"3.0.18-0potato1.2")) flag++;
if (deb_check(release:"2.2", prefix:"php3-mhash", reference:"3.0.18-0potato1.2")) flag++;
if (deb_check(release:"2.2", prefix:"php3-mysql", reference:"3.0.18-0potato1.2")) flag++;
if (deb_check(release:"2.2", prefix:"php3-pgsql", reference:"3.0.18-0potato1.2")) flag++;
if (deb_check(release:"2.2", prefix:"php3-snmp", reference:"3.0.18-0potato1.2")) flag++;
if (deb_check(release:"2.2", prefix:"php3-xml", reference:"3.0.18-0potato1.2")) flag++;
if (deb_check(release:"2.2", prefix:"php4", reference:"4.0.3pl1-0potato4")) flag++;
if (deb_check(release:"2.2", prefix:"php4-cgi", reference:"4.0.3pl1-0potato4")) flag++;
if (deb_check(release:"2.2", prefix:"php4-cgi-gd", reference:"4.0.3pl1-0potato4")) flag++;
if (deb_check(release:"2.2", prefix:"php4-cgi-imap", reference:"4.0.3pl1-0potato4")) flag++;
if (deb_check(release:"2.2", prefix:"php4-cgi-ldap", reference:"4.0.3pl1-0potato4")) flag++;
if (deb_check(release:"2.2", prefix:"php4-cgi-mhash", reference:"4.0.3pl1-0potato4")) flag++;
if (deb_check(release:"2.2", prefix:"php4-cgi-mysql", reference:"4.0.3pl1-0potato4")) flag++;
if (deb_check(release:"2.2", prefix:"php4-cgi-pgsql", reference:"4.0.3pl1-0potato4")) flag++;
if (deb_check(release:"2.2", prefix:"php4-cgi-snmp", reference:"4.0.3pl1-0potato4")) flag++;
if (deb_check(release:"2.2", prefix:"php4-cgi-xml", reference:"4.0.3pl1-0potato4")) flag++;
if (deb_check(release:"2.2", prefix:"php4-dev", reference:"4.0.3pl1-0potato4")) flag++;
if (deb_check(release:"2.2", prefix:"php4-gd", reference:"4.0.3pl1-0potato4")) flag++;
if (deb_check(release:"2.2", prefix:"php4-imap", reference:"4.0.3pl1-0potato4")) flag++;
if (deb_check(release:"2.2", prefix:"php4-ldap", reference:"4.0.3pl1-0potato4")) flag++;
if (deb_check(release:"2.2", prefix:"php4-mhash", reference:"4.0.3pl1-0potato4")) flag++;
if (deb_check(release:"2.2", prefix:"php4-mysql", reference:"4.0.3pl1-0potato4")) flag++;
if (deb_check(release:"2.2", prefix:"php4-pgsql", reference:"4.0.3pl1-0potato4")) flag++;
if (deb_check(release:"2.2", prefix:"php4-snmp", reference:"4.0.3pl1-0potato4")) flag++;
if (deb_check(release:"2.2", prefix:"php4-xml", reference:"4.0.3pl1-0potato4")) flag++;
if (deb_check(release:"3.0", prefix:"caudium-php4", reference:"4.1.2-5")) flag++;
if (deb_check(release:"3.0", prefix:"php3", reference:"3.0.18-23.1woody1")) flag++;
if (deb_check(release:"3.0", prefix:"php3-cgi", reference:"3.0.18-23.1woody1")) flag++;
if (deb_check(release:"3.0", prefix:"php3-cgi-gd", reference:"3.0.18-23.1woody1")) flag++;
if (deb_check(release:"3.0", prefix:"php3-cgi-imap", reference:"3.0.18-23.1woody1")) flag++;
if (deb_check(release:"3.0", prefix:"php3-cgi-ldap", reference:"3.0.18-23.1woody1")) flag++;
if (deb_check(release:"3.0", prefix:"php3-cgi-magick", reference:"3.0.18-23.1woody1")) flag++;
if (deb_check(release:"3.0", prefix:"php3-cgi-mhash", reference:"3.0.18-23.1woody1")) flag++;
if (deb_check(release:"3.0", prefix:"php3-cgi-mysql", reference:"3.0.18-23.1woody1")) flag++;
if (deb_check(release:"3.0", prefix:"php3-cgi-snmp", reference:"3.0.18-23.1woody1")) flag++;
if (deb_check(release:"3.0", prefix:"php3-cgi-xml", reference:"3.0.18-23.1woody1")) flag++;
if (deb_check(release:"3.0", prefix:"php3-dev", reference:"3.0.18-23.1woody1")) flag++;
if (deb_check(release:"3.0", prefix:"php3-doc", reference:"3.0.18-23.1woody1")) flag++;
if (deb_check(release:"3.0", prefix:"php3-gd", reference:"3.0.18-23.1woody1")) flag++;
if (deb_check(release:"3.0", prefix:"php3-imap", reference:"3.0.18-23.1woody1")) flag++;
if (deb_check(release:"3.0", prefix:"php3-ldap", reference:"3.0.18-23.1woody1")) flag++;
if (deb_check(release:"3.0", prefix:"php3-magick", reference:"3.0.18-23.1woody1")) flag++;
if (deb_check(release:"3.0", prefix:"php3-mhash", reference:"3.0.18-23.1woody1")) flag++;
if (deb_check(release:"3.0", prefix:"php3-mysql", reference:"3.0.18-23.1woody1")) flag++;
if (deb_check(release:"3.0", prefix:"php3-snmp", reference:"3.0.18-23.1woody1")) flag++;
if (deb_check(release:"3.0", prefix:"php3-xml", reference:"3.0.18-23.1woody1")) flag++;
if (deb_check(release:"3.0", prefix:"php4", reference:"4.1.2-5")) flag++;
if (deb_check(release:"3.0", prefix:"php4-cgi", reference:"4.1.2-5")) flag++;
if (deb_check(release:"3.0", prefix:"php4-curl", reference:"4.1.2-5")) flag++;
if (deb_check(release:"3.0", prefix:"php4-dev", reference:"4.1.2-5")) flag++;
if (deb_check(release:"3.0", prefix:"php4-domxml", reference:"4.1.2-5")) flag++;
if (deb_check(release:"3.0", prefix:"php4-gd", reference:"4.1.2-5")) flag++;
if (deb_check(release:"3.0", prefix:"php4-imap", reference:"4.1.2-5")) flag++;
if (deb_check(release:"3.0", prefix:"php4-ldap", reference:"4.1.2-5")) flag++;
if (deb_check(release:"3.0", prefix:"php4-mcal", reference:"4.1.2-5")) flag++;
if (deb_check(release:"3.0", prefix:"php4-mhash", reference:"4.1.2-5")) flag++;
if (deb_check(release:"3.0", prefix:"php4-mysql", reference:"4.1.2-5")) flag++;
if (deb_check(release:"3.0", prefix:"php4-odbc", reference:"4.1.2-5")) flag++;
if (deb_check(release:"3.0", prefix:"php4-pear", reference:"4.1.2-5")) flag++;
if (deb_check(release:"3.0", prefix:"php4-recode", reference:"4.1.2-5")) flag++;
if (deb_check(release:"3.0", prefix:"php4-snmp", reference:"4.1.2-5")) flag++;
if (deb_check(release:"3.0", prefix:"php4-sybase", reference:"4.1.2-5")) flag++;
if (deb_check(release:"3.0", prefix:"php4-xslt", reference:"4.1.2-5")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:deb_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
