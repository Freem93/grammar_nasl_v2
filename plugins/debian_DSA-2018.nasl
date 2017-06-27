#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Debian Security Advisory DSA-2018. The text 
# itself is copyright (C) Software in the Public Interest, Inc.
#

include("compat.inc");

if (description)
{
  script_id(45094);
  script_version("$Revision: 1.7 $");
  script_cvs_date("$Date: 2016/05/26 15:53:37 $");

  script_cve_id("CVE-2010-0397");
  script_bugtraq_id(38708);
  script_xref(name:"DSA", value:"2018");

  script_name(english:"Debian DSA-2018-1 : php5 - DoS (crash)");
  script_summary(english:"Checks dpkg output for the updated package");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Debian host is missing a security-related update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Auke van Slooten discovered that PHP 5, an hypertext preprocessor,
crashes (because of a NULL pointer dereference) when processing
invalid XML-RPC requests."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://bugs.debian.org/cgi-bin/bugreport.cgi?bug=573573"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.debian.org/security/2010/dsa-2018"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"Upgrade the php5 packages.

For the stable distribution (lenny), this problem has been fixed in
version 5.2.6.dfsg.1-1+lenny8."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:php5");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:5.0");

  script_set_attribute(attribute:"patch_publication_date", value:"2010/03/18");
  script_set_attribute(attribute:"plugin_publication_date", value:"2010/03/19");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2010-2016 Tenable Network Security, Inc.");
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
if (deb_check(release:"5.0", prefix:"libapache2-mod-php5", reference:"5.2.6.dfsg.1-1+lenny8")) flag++;
if (deb_check(release:"5.0", prefix:"libapache2-mod-php5filter", reference:"5.2.6.dfsg.1-1+lenny8")) flag++;
if (deb_check(release:"5.0", prefix:"php-pear", reference:"5.2.6.dfsg.1-1+lenny8")) flag++;
if (deb_check(release:"5.0", prefix:"php5", reference:"5.2.6.dfsg.1-1+lenny8")) flag++;
if (deb_check(release:"5.0", prefix:"php5-cgi", reference:"5.2.6.dfsg.1-1+lenny8")) flag++;
if (deb_check(release:"5.0", prefix:"php5-cli", reference:"5.2.6.dfsg.1-1+lenny8")) flag++;
if (deb_check(release:"5.0", prefix:"php5-common", reference:"5.2.6.dfsg.1-1+lenny8")) flag++;
if (deb_check(release:"5.0", prefix:"php5-curl", reference:"5.2.6.dfsg.1-1+lenny8")) flag++;
if (deb_check(release:"5.0", prefix:"php5-dbg", reference:"5.2.6.dfsg.1-1+lenny8")) flag++;
if (deb_check(release:"5.0", prefix:"php5-dev", reference:"5.2.6.dfsg.1-1+lenny8")) flag++;
if (deb_check(release:"5.0", prefix:"php5-gd", reference:"5.2.6.dfsg.1-1+lenny8")) flag++;
if (deb_check(release:"5.0", prefix:"php5-gmp", reference:"5.2.6.dfsg.1-1+lenny8")) flag++;
if (deb_check(release:"5.0", prefix:"php5-imap", reference:"5.2.6.dfsg.1-1+lenny8")) flag++;
if (deb_check(release:"5.0", prefix:"php5-interbase", reference:"5.2.6.dfsg.1-1+lenny8")) flag++;
if (deb_check(release:"5.0", prefix:"php5-ldap", reference:"5.2.6.dfsg.1-1+lenny8")) flag++;
if (deb_check(release:"5.0", prefix:"php5-mcrypt", reference:"5.2.6.dfsg.1-1+lenny8")) flag++;
if (deb_check(release:"5.0", prefix:"php5-mhash", reference:"5.2.6.dfsg.1-1+lenny8")) flag++;
if (deb_check(release:"5.0", prefix:"php5-mysql", reference:"5.2.6.dfsg.1-1+lenny8")) flag++;
if (deb_check(release:"5.0", prefix:"php5-odbc", reference:"5.2.6.dfsg.1-1+lenny8")) flag++;
if (deb_check(release:"5.0", prefix:"php5-pgsql", reference:"5.2.6.dfsg.1-1+lenny8")) flag++;
if (deb_check(release:"5.0", prefix:"php5-pspell", reference:"5.2.6.dfsg.1-1+lenny8")) flag++;
if (deb_check(release:"5.0", prefix:"php5-recode", reference:"5.2.6.dfsg.1-1+lenny8")) flag++;
if (deb_check(release:"5.0", prefix:"php5-snmp", reference:"5.2.6.dfsg.1-1+lenny8")) flag++;
if (deb_check(release:"5.0", prefix:"php5-sqlite", reference:"5.2.6.dfsg.1-1+lenny8")) flag++;
if (deb_check(release:"5.0", prefix:"php5-sybase", reference:"5.2.6.dfsg.1-1+lenny8")) flag++;
if (deb_check(release:"5.0", prefix:"php5-tidy", reference:"5.2.6.dfsg.1-1+lenny8")) flag++;
if (deb_check(release:"5.0", prefix:"php5-xmlrpc", reference:"5.2.6.dfsg.1-1+lenny8")) flag++;
if (deb_check(release:"5.0", prefix:"php5-xsl", reference:"5.2.6.dfsg.1-1+lenny8")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:deb_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
