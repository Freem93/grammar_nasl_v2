#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Debian Security Advisory DSA-2943. The text 
# itself is copyright (C) Software in the Public Interest, Inc.
#

include("compat.inc");

if (description)
{
  script_id(74279);
  script_version("$Revision: 1.5 $");
  script_cvs_date("$Date: 2015/07/20 14:56:55 $");

  script_cve_id("CVE-2014-0185", "CVE-2014-0237", "CVE-2014-0238", "CVE-2014-2270");
  script_bugtraq_id(66002, 67118);
  script_osvdb_id(107559, 107560);
  script_xref(name:"DSA", value:"2943");

  script_name(english:"Debian DSA-2943-1 : php5 - security update");
  script_summary(english:"Checks dpkg output for the updated package");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Debian host is missing a security-related update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Several vulnerabilities were found in PHP, a general-purpose scripting
language commonly used for web application development :

  - CVE-2014-0185
    The default PHP FPM socket permission has been changed
    from 0666 to 0660 to mitigate a security vulnerability (
    CVE-2014-0185 ) in PHP FPM that allowed any local user
    to run a PHP code under the active user of FPM process
    via crafted FastCGI client.

  The default Debian setup now correctly sets the listen.owner and
  listen.group to www-data:www-data in default php-fpm.conf. If you
  have more FPM instances or a webserver not running under www-data
  user you need to adjust the configuration of FPM pools in
  /etc/php5/fpm/pool.d/ so the accessing process has rights to access
  the socket.

  - CVE-2014-0237 / CVE-2014-0238
    Denial of service in the CDF parser of the fileinfo
    module.

  - CVE-2014-2270
    Denial of service in the fileinfo module."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2014-0185"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2014-0185"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2014-0237"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2014-0238"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2014-2270"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://packages.debian.org/source/wheezy/php5"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.debian.org/security/2014/dsa-2943"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"Upgrade the php5 packages.

For the stable distribution (wheezy), these problems have been fixed
in version 5.4.4-14+deb7u10."
  );
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:php5");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:7.0");

  script_set_attribute(attribute:"patch_publication_date", value:"2014/06/01");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/06/03");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2014-2015 Tenable Network Security, Inc.");
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
if (deb_check(release:"7.0", prefix:"libapache2-mod-php5", reference:"5.4.4-14+deb7u10")) flag++;
if (deb_check(release:"7.0", prefix:"libapache2-mod-php5filter", reference:"5.4.4-14+deb7u10")) flag++;
if (deb_check(release:"7.0", prefix:"libphp5-embed", reference:"5.4.4-14+deb7u10")) flag++;
if (deb_check(release:"7.0", prefix:"php-pear", reference:"5.4.4-14+deb7u10")) flag++;
if (deb_check(release:"7.0", prefix:"php5", reference:"5.4.4-14+deb7u10")) flag++;
if (deb_check(release:"7.0", prefix:"php5-cgi", reference:"5.4.4-14+deb7u10")) flag++;
if (deb_check(release:"7.0", prefix:"php5-cli", reference:"5.4.4-14+deb7u10")) flag++;
if (deb_check(release:"7.0", prefix:"php5-common", reference:"5.4.4-14+deb7u10")) flag++;
if (deb_check(release:"7.0", prefix:"php5-curl", reference:"5.4.4-14+deb7u10")) flag++;
if (deb_check(release:"7.0", prefix:"php5-dbg", reference:"5.4.4-14+deb7u10")) flag++;
if (deb_check(release:"7.0", prefix:"php5-dev", reference:"5.4.4-14+deb7u10")) flag++;
if (deb_check(release:"7.0", prefix:"php5-enchant", reference:"5.4.4-14+deb7u10")) flag++;
if (deb_check(release:"7.0", prefix:"php5-fpm", reference:"5.4.4-14+deb7u10")) flag++;
if (deb_check(release:"7.0", prefix:"php5-gd", reference:"5.4.4-14+deb7u10")) flag++;
if (deb_check(release:"7.0", prefix:"php5-gmp", reference:"5.4.4-14+deb7u10")) flag++;
if (deb_check(release:"7.0", prefix:"php5-imap", reference:"5.4.4-14+deb7u10")) flag++;
if (deb_check(release:"7.0", prefix:"php5-interbase", reference:"5.4.4-14+deb7u10")) flag++;
if (deb_check(release:"7.0", prefix:"php5-intl", reference:"5.4.4-14+deb7u10")) flag++;
if (deb_check(release:"7.0", prefix:"php5-ldap", reference:"5.4.4-14+deb7u10")) flag++;
if (deb_check(release:"7.0", prefix:"php5-mcrypt", reference:"5.4.4-14+deb7u10")) flag++;
if (deb_check(release:"7.0", prefix:"php5-mysql", reference:"5.4.4-14+deb7u10")) flag++;
if (deb_check(release:"7.0", prefix:"php5-mysqlnd", reference:"5.4.4-14+deb7u10")) flag++;
if (deb_check(release:"7.0", prefix:"php5-odbc", reference:"5.4.4-14+deb7u10")) flag++;
if (deb_check(release:"7.0", prefix:"php5-pgsql", reference:"5.4.4-14+deb7u10")) flag++;
if (deb_check(release:"7.0", prefix:"php5-pspell", reference:"5.4.4-14+deb7u10")) flag++;
if (deb_check(release:"7.0", prefix:"php5-recode", reference:"5.4.4-14+deb7u10")) flag++;
if (deb_check(release:"7.0", prefix:"php5-snmp", reference:"5.4.4-14+deb7u10")) flag++;
if (deb_check(release:"7.0", prefix:"php5-sqlite", reference:"5.4.4-14+deb7u10")) flag++;
if (deb_check(release:"7.0", prefix:"php5-sybase", reference:"5.4.4-14+deb7u10")) flag++;
if (deb_check(release:"7.0", prefix:"php5-tidy", reference:"5.4.4-14+deb7u10")) flag++;
if (deb_check(release:"7.0", prefix:"php5-xmlrpc", reference:"5.4.4-14+deb7u10")) flag++;
if (deb_check(release:"7.0", prefix:"php5-xsl", reference:"5.4.4-14+deb7u10")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:deb_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
