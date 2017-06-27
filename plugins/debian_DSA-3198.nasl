#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Debian Security Advisory DSA-3198. The text 
# itself is copyright (C) Software in the Public Interest, Inc.
#

include("compat.inc");

if (description)
{
  script_id(81982);
  script_version("$Revision: 1.13 $");
  script_cvs_date("$Date: 2016/05/19 17:45:44 $");

  script_cve_id("CVE-2015-2301", "CVE-2015-2331", "CVE-2015-2348", "CVE-2015-2787");
  script_bugtraq_id(73037, 73182);
  script_osvdb_id(119650, 119693);
  script_xref(name:"DSA", value:"3198");

  script_name(english:"Debian DSA-3198-1 : php5 - security update");
  script_summary(english:"Checks dpkg output for the updated package");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Debian host is missing a security-related update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Multiple vulnerabilities have been discovered in the PHP language :

  - CVE-2015-2301
    Use-after-free in the phar extension.

  - CVE-2015-2331
    Emmanuel Law discovered an integer overflow in the
    processing of ZIP archives, resulting in denial of
    service or potentially the execution of arbitrary code."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2015-2301"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2015-2331"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://packages.debian.org/source/wheezy/php5"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.debian.org/security/2015/dsa-3198"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"Upgrade the php5 packages.

For the stable distribution (wheezy), these problems have been fixed
in version 5.4.39-0+deb7u1. This update also fixes a regression in the
curl support introduced in DSA 3195."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:php5");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:7.0");

  script_set_attribute(attribute:"patch_publication_date", value:"2015/03/20");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/03/23");
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
if (deb_check(release:"7.0", prefix:"libapache2-mod-php5", reference:"5.4.39-0+deb7u1")) flag++;
if (deb_check(release:"7.0", prefix:"libapache2-mod-php5filter", reference:"5.4.39-0+deb7u1")) flag++;
if (deb_check(release:"7.0", prefix:"libphp5-embed", reference:"5.4.39-0+deb7u1")) flag++;
if (deb_check(release:"7.0", prefix:"php-pear", reference:"5.4.39-0+deb7u1")) flag++;
if (deb_check(release:"7.0", prefix:"php5", reference:"5.4.39-0+deb7u1")) flag++;
if (deb_check(release:"7.0", prefix:"php5-cgi", reference:"5.4.39-0+deb7u1")) flag++;
if (deb_check(release:"7.0", prefix:"php5-cli", reference:"5.4.39-0+deb7u1")) flag++;
if (deb_check(release:"7.0", prefix:"php5-common", reference:"5.4.39-0+deb7u1")) flag++;
if (deb_check(release:"7.0", prefix:"php5-curl", reference:"5.4.39-0+deb7u1")) flag++;
if (deb_check(release:"7.0", prefix:"php5-dbg", reference:"5.4.39-0+deb7u1")) flag++;
if (deb_check(release:"7.0", prefix:"php5-dev", reference:"5.4.39-0+deb7u1")) flag++;
if (deb_check(release:"7.0", prefix:"php5-enchant", reference:"5.4.39-0+deb7u1")) flag++;
if (deb_check(release:"7.0", prefix:"php5-fpm", reference:"5.4.39-0+deb7u1")) flag++;
if (deb_check(release:"7.0", prefix:"php5-gd", reference:"5.4.39-0+deb7u1")) flag++;
if (deb_check(release:"7.0", prefix:"php5-gmp", reference:"5.4.39-0+deb7u1")) flag++;
if (deb_check(release:"7.0", prefix:"php5-imap", reference:"5.4.39-0+deb7u1")) flag++;
if (deb_check(release:"7.0", prefix:"php5-interbase", reference:"5.4.39-0+deb7u1")) flag++;
if (deb_check(release:"7.0", prefix:"php5-intl", reference:"5.4.39-0+deb7u1")) flag++;
if (deb_check(release:"7.0", prefix:"php5-ldap", reference:"5.4.39-0+deb7u1")) flag++;
if (deb_check(release:"7.0", prefix:"php5-mcrypt", reference:"5.4.39-0+deb7u1")) flag++;
if (deb_check(release:"7.0", prefix:"php5-mysql", reference:"5.4.39-0+deb7u1")) flag++;
if (deb_check(release:"7.0", prefix:"php5-mysqlnd", reference:"5.4.39-0+deb7u1")) flag++;
if (deb_check(release:"7.0", prefix:"php5-odbc", reference:"5.4.39-0+deb7u1")) flag++;
if (deb_check(release:"7.0", prefix:"php5-pgsql", reference:"5.4.39-0+deb7u1")) flag++;
if (deb_check(release:"7.0", prefix:"php5-pspell", reference:"5.4.39-0+deb7u1")) flag++;
if (deb_check(release:"7.0", prefix:"php5-recode", reference:"5.4.39-0+deb7u1")) flag++;
if (deb_check(release:"7.0", prefix:"php5-snmp", reference:"5.4.39-0+deb7u1")) flag++;
if (deb_check(release:"7.0", prefix:"php5-sqlite", reference:"5.4.39-0+deb7u1")) flag++;
if (deb_check(release:"7.0", prefix:"php5-sybase", reference:"5.4.39-0+deb7u1")) flag++;
if (deb_check(release:"7.0", prefix:"php5-tidy", reference:"5.4.39-0+deb7u1")) flag++;
if (deb_check(release:"7.0", prefix:"php5-xmlrpc", reference:"5.4.39-0+deb7u1")) flag++;
if (deb_check(release:"7.0", prefix:"php5-xsl", reference:"5.4.39-0+deb7u1")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:deb_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
