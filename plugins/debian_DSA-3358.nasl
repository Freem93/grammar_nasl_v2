#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Debian Security Advisory DSA-3358. The text 
# itself is copyright (C) Software in the Public Interest, Inc.
#

include("compat.inc");

if (description)
{
  script_id(85914);
  script_version("$Revision: 2.9 $");
  script_cvs_date("$Date: 2016/12/06 20:25:08 $");

  script_cve_id("CVE-2015-6834", "CVE-2015-6835", "CVE-2015-6836", "CVE-2015-6837", "CVE-2015-6838");
  script_osvdb_id(126951, 126952, 126953, 126954, 126962, 126989);
  script_xref(name:"DSA", value:"3358");

  script_name(english:"Debian DSA-3358-1 : php5 - security update");
  script_summary(english:"Checks dpkg output for the updated package");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Debian host is missing a security-related update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Several vulnerabilities were found in PHP, a general-purpose scripting
language commonly used for web application development.

The vulnerabilities are addressed by upgrading PHP to new upstream
versions (5.4.45 and 5.6.13), which include additional bug fixes.
Please refer to the upstream changelog for more information :

  - https://php.net/ChangeLog-5.php#5.4.45
  - https://php.net/ChangeLog-5.php#5.6.13"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://php.net/ChangeLog-5.php#5.4.45"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://php.net/ChangeLog-5.php#5.6.13"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://packages.debian.org/source/wheezy/php5"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://packages.debian.org/source/jessie/php5"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.debian.org/security/2015/dsa-3358"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"Upgrade the php5 packages.

For the oldstable distribution (wheezy), these problems have been
fixed in version 5.4.45-0+deb7u1.


For the stable distribution (jessie), these problems have been fixed
in version 5.6.13+dfsg-0+deb8u1."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:ND");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:php5");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:7.0");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:8.0");

  script_set_attribute(attribute:"patch_publication_date", value:"2015/09/13");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/09/14");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2015-2016 Tenable Network Security, Inc.");
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
if (deb_check(release:"7.0", prefix:"libapache2-mod-php5", reference:"5.4.45-0+deb7u1")) flag++;
if (deb_check(release:"7.0", prefix:"libapache2-mod-php5filter", reference:"5.4.45-0+deb7u1")) flag++;
if (deb_check(release:"7.0", prefix:"libphp5-embed", reference:"5.4.45-0+deb7u1")) flag++;
if (deb_check(release:"7.0", prefix:"php-pear", reference:"5.4.45-0+deb7u1")) flag++;
if (deb_check(release:"7.0", prefix:"php5", reference:"5.4.45-0+deb7u1")) flag++;
if (deb_check(release:"7.0", prefix:"php5-cgi", reference:"5.4.45-0+deb7u1")) flag++;
if (deb_check(release:"7.0", prefix:"php5-cli", reference:"5.4.45-0+deb7u1")) flag++;
if (deb_check(release:"7.0", prefix:"php5-common", reference:"5.4.45-0+deb7u1")) flag++;
if (deb_check(release:"7.0", prefix:"php5-curl", reference:"5.4.45-0+deb7u1")) flag++;
if (deb_check(release:"7.0", prefix:"php5-dbg", reference:"5.4.45-0+deb7u1")) flag++;
if (deb_check(release:"7.0", prefix:"php5-dev", reference:"5.4.45-0+deb7u1")) flag++;
if (deb_check(release:"7.0", prefix:"php5-enchant", reference:"5.4.45-0+deb7u1")) flag++;
if (deb_check(release:"7.0", prefix:"php5-fpm", reference:"5.4.45-0+deb7u1")) flag++;
if (deb_check(release:"7.0", prefix:"php5-gd", reference:"5.4.45-0+deb7u1")) flag++;
if (deb_check(release:"7.0", prefix:"php5-gmp", reference:"5.4.45-0+deb7u1")) flag++;
if (deb_check(release:"7.0", prefix:"php5-imap", reference:"5.4.45-0+deb7u1")) flag++;
if (deb_check(release:"7.0", prefix:"php5-interbase", reference:"5.4.45-0+deb7u1")) flag++;
if (deb_check(release:"7.0", prefix:"php5-intl", reference:"5.4.45-0+deb7u1")) flag++;
if (deb_check(release:"7.0", prefix:"php5-ldap", reference:"5.4.45-0+deb7u1")) flag++;
if (deb_check(release:"7.0", prefix:"php5-mcrypt", reference:"5.4.45-0+deb7u1")) flag++;
if (deb_check(release:"7.0", prefix:"php5-mysql", reference:"5.4.45-0+deb7u1")) flag++;
if (deb_check(release:"7.0", prefix:"php5-mysqlnd", reference:"5.4.45-0+deb7u1")) flag++;
if (deb_check(release:"7.0", prefix:"php5-odbc", reference:"5.4.45-0+deb7u1")) flag++;
if (deb_check(release:"7.0", prefix:"php5-pgsql", reference:"5.4.45-0+deb7u1")) flag++;
if (deb_check(release:"7.0", prefix:"php5-pspell", reference:"5.4.45-0+deb7u1")) flag++;
if (deb_check(release:"7.0", prefix:"php5-recode", reference:"5.4.45-0+deb7u1")) flag++;
if (deb_check(release:"7.0", prefix:"php5-snmp", reference:"5.4.45-0+deb7u1")) flag++;
if (deb_check(release:"7.0", prefix:"php5-sqlite", reference:"5.4.45-0+deb7u1")) flag++;
if (deb_check(release:"7.0", prefix:"php5-sybase", reference:"5.4.45-0+deb7u1")) flag++;
if (deb_check(release:"7.0", prefix:"php5-tidy", reference:"5.4.45-0+deb7u1")) flag++;
if (deb_check(release:"7.0", prefix:"php5-xmlrpc", reference:"5.4.45-0+deb7u1")) flag++;
if (deb_check(release:"7.0", prefix:"php5-xsl", reference:"5.4.45-0+deb7u1")) flag++;
if (deb_check(release:"8.0", prefix:"libapache2-mod-php5", reference:"5.6.13+dfsg-0+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"libapache2-mod-php5filter", reference:"5.6.13+dfsg-0+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"libphp5-embed", reference:"5.6.13+dfsg-0+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"php-pear", reference:"5.6.13+dfsg-0+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"php5", reference:"5.6.13+dfsg-0+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"php5-cgi", reference:"5.6.13+dfsg-0+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"php5-cli", reference:"5.6.13+dfsg-0+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"php5-common", reference:"5.6.13+dfsg-0+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"php5-curl", reference:"5.6.13+dfsg-0+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"php5-dbg", reference:"5.6.13+dfsg-0+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"php5-dev", reference:"5.6.13+dfsg-0+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"php5-enchant", reference:"5.6.13+dfsg-0+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"php5-fpm", reference:"5.6.13+dfsg-0+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"php5-gd", reference:"5.6.13+dfsg-0+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"php5-gmp", reference:"5.6.13+dfsg-0+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"php5-imap", reference:"5.6.13+dfsg-0+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"php5-interbase", reference:"5.6.13+dfsg-0+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"php5-intl", reference:"5.6.13+dfsg-0+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"php5-ldap", reference:"5.6.13+dfsg-0+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"php5-mcrypt", reference:"5.6.13+dfsg-0+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"php5-mysql", reference:"5.6.13+dfsg-0+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"php5-mysqlnd", reference:"5.6.13+dfsg-0+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"php5-odbc", reference:"5.6.13+dfsg-0+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"php5-pgsql", reference:"5.6.13+dfsg-0+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"php5-phpdbg", reference:"5.6.13+dfsg-0+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"php5-pspell", reference:"5.6.13+dfsg-0+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"php5-readline", reference:"5.6.13+dfsg-0+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"php5-recode", reference:"5.6.13+dfsg-0+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"php5-snmp", reference:"5.6.13+dfsg-0+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"php5-sqlite", reference:"5.6.13+dfsg-0+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"php5-sybase", reference:"5.6.13+dfsg-0+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"php5-tidy", reference:"5.6.13+dfsg-0+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"php5-xmlrpc", reference:"5.6.13+dfsg-0+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"php5-xsl", reference:"5.6.13+dfsg-0+deb8u1")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:deb_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
