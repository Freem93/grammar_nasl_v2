#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Debian Security Advisory DSA-3602. The text 
# itself is copyright (C) Software in the Public Interest, Inc.
#

include("compat.inc");

if (description)
{
  script_id(91615);
  script_version("$Revision: 2.4 $");
  script_cvs_date("$Date: 2016/12/06 20:25:09 $");

  script_cve_id("CVE-2013-7456", "CVE-2016-3074", "CVE-2016-4537", "CVE-2016-4538", "CVE-2016-4539", "CVE-2016-4540", "CVE-2016-4541", "CVE-2016-4542", "CVE-2016-4543", "CVE-2016-4544", "CVE-2016-5093", "CVE-2016-5094", "CVE-2016-5095", "CVE-2016-5096");
  script_osvdb_id(137447, 137781, 137782, 137783, 137784, 138996, 138997, 139004, 139005);
  script_xref(name:"DSA", value:"3602");

  script_name(english:"Debian DSA-3602-1 : php5 - security update");
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

The vulnerabilities are addressed by upgrading PHP to the new upstream
version 5.6.22, which includes additional bug fixes. Please refer to
the upstream changelog for more information :

  - https://php.net/ChangeLog-5.php#5.6.21
  - https://php.net/ChangeLog-5.php#5.6.22"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://php.net/ChangeLog-5.php#5.6.21"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://php.net/ChangeLog-5.php#5.6.22"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://packages.debian.org/source/jessie/php5"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.debian.org/security/2016/dsa-3602"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"Upgrade the php5 packages.

For the stable distribution (jessie), these problems have been fixed
in version 5.6.22+dfsg-0+deb8u1."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:ND");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:php5");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:8.0");

  script_set_attribute(attribute:"patch_publication_date", value:"2016/06/14");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/06/15");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2016 Tenable Network Security, Inc.");
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
if (deb_check(release:"8.0", prefix:"libapache2-mod-php5", reference:"5.6.22+dfsg-0+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"libapache2-mod-php5filter", reference:"5.6.22+dfsg-0+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"libphp5-embed", reference:"5.6.22+dfsg-0+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"php-pear", reference:"5.6.22+dfsg-0+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"php5", reference:"5.6.22+dfsg-0+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"php5-cgi", reference:"5.6.22+dfsg-0+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"php5-cli", reference:"5.6.22+dfsg-0+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"php5-common", reference:"5.6.22+dfsg-0+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"php5-curl", reference:"5.6.22+dfsg-0+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"php5-dbg", reference:"5.6.22+dfsg-0+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"php5-dev", reference:"5.6.22+dfsg-0+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"php5-enchant", reference:"5.6.22+dfsg-0+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"php5-fpm", reference:"5.6.22+dfsg-0+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"php5-gd", reference:"5.6.22+dfsg-0+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"php5-gmp", reference:"5.6.22+dfsg-0+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"php5-imap", reference:"5.6.22+dfsg-0+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"php5-interbase", reference:"5.6.22+dfsg-0+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"php5-intl", reference:"5.6.22+dfsg-0+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"php5-ldap", reference:"5.6.22+dfsg-0+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"php5-mcrypt", reference:"5.6.22+dfsg-0+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"php5-mysql", reference:"5.6.22+dfsg-0+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"php5-mysqlnd", reference:"5.6.22+dfsg-0+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"php5-odbc", reference:"5.6.22+dfsg-0+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"php5-pgsql", reference:"5.6.22+dfsg-0+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"php5-phpdbg", reference:"5.6.22+dfsg-0+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"php5-pspell", reference:"5.6.22+dfsg-0+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"php5-readline", reference:"5.6.22+dfsg-0+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"php5-recode", reference:"5.6.22+dfsg-0+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"php5-snmp", reference:"5.6.22+dfsg-0+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"php5-sqlite", reference:"5.6.22+dfsg-0+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"php5-sybase", reference:"5.6.22+dfsg-0+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"php5-tidy", reference:"5.6.22+dfsg-0+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"php5-xmlrpc", reference:"5.6.22+dfsg-0+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"php5-xsl", reference:"5.6.22+dfsg-0+deb8u1")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:deb_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
