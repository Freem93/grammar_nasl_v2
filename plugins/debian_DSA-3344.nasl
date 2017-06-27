#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Debian Security Advisory DSA-3344. The text 
# itself is copyright (C) Software in the Public Interest, Inc.
#

include("compat.inc");

if (description)
{
  script_id(85664);
  script_version("$Revision: 2.9 $");
  script_cvs_date("$Date: 2016/12/06 20:25:07 $");

  script_cve_id("CVE-2015-4598", "CVE-2015-4643", "CVE-2015-4644", "CVE-2015-5589", "CVE-2015-5590", "CVE-2015-6831", "CVE-2015-6832", "CVE-2015-6833");
  script_osvdb_id(117588, 122126, 123148, 124239, 124242);
  script_xref(name:"DSA", value:"3344");

  script_name(english:"Debian DSA-3344-1 : php5 - security update");
  script_summary(english:"Checks dpkg output for the updated package");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Debian host is missing a security-related update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Multiple vulnerabilities have been discovered in the PHP language :

  - CVE-2015-4598
    thoger at redhat dot com discovered that paths
    containing a NUL character were improperly handled, thus
    allowing an attacker to manipulate unexpected files on
    the server.

  - CVE-2015-4643
    Max Spelsberg discovered an integer overflow flaw
    leading to a heap-based buffer overflow in PHP's FTP
    extension, when parsing listings in FTP server
    responses. This could lead to a a crash or execution of
    arbitrary code.

  - CVE-2015-4644
    A denial of service through a crash could be caused by a
    segfault in the php_pgsql_meta_data function.

  - CVE-2015-5589
    kwrnel at hotmail dot com discovered that PHP could
    crash when processing an invalid phar file, thus leading
    to a denial of service.

  - CVE-2015-5590
    jared at enhancesoft dot com discovered a buffer
    overflow in the phar_fix_filepath function, that could
    causes a crash or execution of arbitrary code.

  - Additionally, several other vulnerabilites were fixed :

    sean dot heelan at gmail dot com discovered a problem in
    the unserialization of some items, that could lead to
    arbitrary code execution.

  stewie at mail dot ru discovered that the phar extension improperly
  handled zip archives with relative paths, which would allow an
  attacker to overwrite files outside of the destination directory.

  taoguangchen at icloud dot com discovered several use-after-free
  vulnerabilities that could lead to arbitrary code execution."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2015-4598"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2015-4643"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2015-4644"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2015-5589"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2015-5590"
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
    value:"http://www.debian.org/security/2015/dsa-3344"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"Upgrade the php5 packages.

For the oldstable distribution (wheezy), these problems have been
fixed in version 5.4.44-0+deb7u1.

For the stable distribution (jessie), these problems have been fixed
in version 5.6.12+dfsg-0+deb8u1."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:ND");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:X");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:php5");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:7.0");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:8.0");

  script_set_attribute(attribute:"patch_publication_date", value:"2015/08/27");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/08/28");
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
if (deb_check(release:"7.0", prefix:"libapache2-mod-php5", reference:"5.4.44-0+deb7u1")) flag++;
if (deb_check(release:"7.0", prefix:"libapache2-mod-php5filter", reference:"5.4.44-0+deb7u1")) flag++;
if (deb_check(release:"7.0", prefix:"libphp5-embed", reference:"5.4.44-0+deb7u1")) flag++;
if (deb_check(release:"7.0", prefix:"php-pear", reference:"5.4.44-0+deb7u1")) flag++;
if (deb_check(release:"7.0", prefix:"php5", reference:"5.4.44-0+deb7u1")) flag++;
if (deb_check(release:"7.0", prefix:"php5-cgi", reference:"5.4.44-0+deb7u1")) flag++;
if (deb_check(release:"7.0", prefix:"php5-cli", reference:"5.4.44-0+deb7u1")) flag++;
if (deb_check(release:"7.0", prefix:"php5-common", reference:"5.4.44-0+deb7u1")) flag++;
if (deb_check(release:"7.0", prefix:"php5-curl", reference:"5.4.44-0+deb7u1")) flag++;
if (deb_check(release:"7.0", prefix:"php5-dbg", reference:"5.4.44-0+deb7u1")) flag++;
if (deb_check(release:"7.0", prefix:"php5-dev", reference:"5.4.44-0+deb7u1")) flag++;
if (deb_check(release:"7.0", prefix:"php5-enchant", reference:"5.4.44-0+deb7u1")) flag++;
if (deb_check(release:"7.0", prefix:"php5-fpm", reference:"5.4.44-0+deb7u1")) flag++;
if (deb_check(release:"7.0", prefix:"php5-gd", reference:"5.4.44-0+deb7u1")) flag++;
if (deb_check(release:"7.0", prefix:"php5-gmp", reference:"5.4.44-0+deb7u1")) flag++;
if (deb_check(release:"7.0", prefix:"php5-imap", reference:"5.4.44-0+deb7u1")) flag++;
if (deb_check(release:"7.0", prefix:"php5-interbase", reference:"5.4.44-0+deb7u1")) flag++;
if (deb_check(release:"7.0", prefix:"php5-intl", reference:"5.4.44-0+deb7u1")) flag++;
if (deb_check(release:"7.0", prefix:"php5-ldap", reference:"5.4.44-0+deb7u1")) flag++;
if (deb_check(release:"7.0", prefix:"php5-mcrypt", reference:"5.4.44-0+deb7u1")) flag++;
if (deb_check(release:"7.0", prefix:"php5-mysql", reference:"5.4.44-0+deb7u1")) flag++;
if (deb_check(release:"7.0", prefix:"php5-mysqlnd", reference:"5.4.44-0+deb7u1")) flag++;
if (deb_check(release:"7.0", prefix:"php5-odbc", reference:"5.4.44-0+deb7u1")) flag++;
if (deb_check(release:"7.0", prefix:"php5-pgsql", reference:"5.4.44-0+deb7u1")) flag++;
if (deb_check(release:"7.0", prefix:"php5-pspell", reference:"5.4.44-0+deb7u1")) flag++;
if (deb_check(release:"7.0", prefix:"php5-recode", reference:"5.4.44-0+deb7u1")) flag++;
if (deb_check(release:"7.0", prefix:"php5-snmp", reference:"5.4.44-0+deb7u1")) flag++;
if (deb_check(release:"7.0", prefix:"php5-sqlite", reference:"5.4.44-0+deb7u1")) flag++;
if (deb_check(release:"7.0", prefix:"php5-sybase", reference:"5.4.44-0+deb7u1")) flag++;
if (deb_check(release:"7.0", prefix:"php5-tidy", reference:"5.4.44-0+deb7u1")) flag++;
if (deb_check(release:"7.0", prefix:"php5-xmlrpc", reference:"5.4.44-0+deb7u1")) flag++;
if (deb_check(release:"7.0", prefix:"php5-xsl", reference:"5.4.44-0+deb7u1")) flag++;
if (deb_check(release:"8.0", prefix:"libapache2-mod-php5", reference:"5.6.12+dfsg-0+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"libapache2-mod-php5filter", reference:"5.6.12+dfsg-0+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"libphp5-embed", reference:"5.6.12+dfsg-0+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"php-pear", reference:"5.6.12+dfsg-0+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"php5", reference:"5.6.12+dfsg-0+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"php5-cgi", reference:"5.6.12+dfsg-0+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"php5-cli", reference:"5.6.12+dfsg-0+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"php5-common", reference:"5.6.12+dfsg-0+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"php5-curl", reference:"5.6.12+dfsg-0+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"php5-dbg", reference:"5.6.12+dfsg-0+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"php5-dev", reference:"5.6.12+dfsg-0+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"php5-enchant", reference:"5.6.12+dfsg-0+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"php5-fpm", reference:"5.6.12+dfsg-0+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"php5-gd", reference:"5.6.12+dfsg-0+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"php5-gmp", reference:"5.6.12+dfsg-0+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"php5-imap", reference:"5.6.12+dfsg-0+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"php5-interbase", reference:"5.6.12+dfsg-0+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"php5-intl", reference:"5.6.12+dfsg-0+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"php5-ldap", reference:"5.6.12+dfsg-0+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"php5-mcrypt", reference:"5.6.12+dfsg-0+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"php5-mysql", reference:"5.6.12+dfsg-0+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"php5-mysqlnd", reference:"5.6.12+dfsg-0+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"php5-odbc", reference:"5.6.12+dfsg-0+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"php5-pgsql", reference:"5.6.12+dfsg-0+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"php5-phpdbg", reference:"5.6.12+dfsg-0+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"php5-pspell", reference:"5.6.12+dfsg-0+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"php5-readline", reference:"5.6.12+dfsg-0+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"php5-recode", reference:"5.6.12+dfsg-0+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"php5-snmp", reference:"5.6.12+dfsg-0+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"php5-sqlite", reference:"5.6.12+dfsg-0+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"php5-sybase", reference:"5.6.12+dfsg-0+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"php5-tidy", reference:"5.6.12+dfsg-0+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"php5-xmlrpc", reference:"5.6.12+dfsg-0+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"php5-xsl", reference:"5.6.12+dfsg-0+deb8u1")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:deb_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
