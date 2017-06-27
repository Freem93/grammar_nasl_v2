#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Debian Security Advisory DSA-3008. The text 
# itself is copyright (C) Software in the Public Interest, Inc.
#

include("compat.inc");

if (description)
{
  script_id(77307);
  script_version("$Revision: 1.9 $");
  script_cvs_date("$Date: 2016/05/05 16:01:11 $");

  script_cve_id("CVE-2014-3538", "CVE-2014-3587", "CVE-2014-3597", "CVE-2014-4670");
  script_bugtraq_id(68348, 68513, 69325);
  script_osvdb_id(104208, 107994, 108947, 110250, 110251);
  script_xref(name:"DSA", value:"3008");

  script_name(english:"Debian DSA-3008-1 : php5 - security update");
  script_summary(english:"Checks dpkg output for the updated package");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Debian host is missing a security-related update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Several vulnerabilities were found in PHP, a general-purpose scripting
language commonly used for web application development. The Common
Vulnerabilities and Exposures project identifies the following
problems :

  - CVE-2014-3538
    It was discovered that the original fix for
    CVE-2013-7345 did not sufficiently address the problem.
    A remote attacker could still cause a denial of service
    (CPU consumption) via a specially crafted input file
    that triggers backtracking during processing of an awk
    regular expression rule.

  - CVE-2014-3587
    It was discovered that the CDF parser of the fileinfo
    module does not properly process malformed files in the
    Composite Document File (CDF) format, leading to
    crashes.

  - CVE-2014-3597
    It was discovered that the original fix for
    CVE-2014-4049 did not completely address the issue. A
    malicious server or man-in-the-middle attacker could
    cause a denial of service (crash) and possibly execute
    arbitrary code via a crafted DNS TXT record.

  - CVE-2014-4670
    It was discovered that PHP incorrectly handled certain
    SPL Iterators. A local attacker could use this flaw to
    cause PHP to crash, resulting in a denial of service."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2014-3538"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2013-7345"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2014-3587"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2014-3597"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2014-4049"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2014-4670"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://packages.debian.org/source/wheezy/php5"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.debian.org/security/2014/dsa-3008"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"Upgrade the php5 packages.

For the stable distribution (wheezy), these problems have been fixed
in version 5.4.4-14+deb7u13. In addition, this update contains several
bugfixes originally targeted for the upcoming Wheezy point release."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:php5");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:7.0");

  script_set_attribute(attribute:"patch_publication_date", value:"2014/08/21");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/08/22");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2014-2016 Tenable Network Security, Inc.");
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
if (deb_check(release:"7.0", prefix:"libapache2-mod-php5", reference:"5.4.4-14+deb7u13")) flag++;
if (deb_check(release:"7.0", prefix:"libapache2-mod-php5filter", reference:"5.4.4-14+deb7u13")) flag++;
if (deb_check(release:"7.0", prefix:"libphp5-embed", reference:"5.4.4-14+deb7u13")) flag++;
if (deb_check(release:"7.0", prefix:"php-pear", reference:"5.4.4-14+deb7u13")) flag++;
if (deb_check(release:"7.0", prefix:"php5", reference:"5.4.4-14+deb7u13")) flag++;
if (deb_check(release:"7.0", prefix:"php5-cgi", reference:"5.4.4-14+deb7u13")) flag++;
if (deb_check(release:"7.0", prefix:"php5-cli", reference:"5.4.4-14+deb7u13")) flag++;
if (deb_check(release:"7.0", prefix:"php5-common", reference:"5.4.4-14+deb7u13")) flag++;
if (deb_check(release:"7.0", prefix:"php5-curl", reference:"5.4.4-14+deb7u13")) flag++;
if (deb_check(release:"7.0", prefix:"php5-dbg", reference:"5.4.4-14+deb7u13")) flag++;
if (deb_check(release:"7.0", prefix:"php5-dev", reference:"5.4.4-14+deb7u13")) flag++;
if (deb_check(release:"7.0", prefix:"php5-enchant", reference:"5.4.4-14+deb7u13")) flag++;
if (deb_check(release:"7.0", prefix:"php5-fpm", reference:"5.4.4-14+deb7u13")) flag++;
if (deb_check(release:"7.0", prefix:"php5-gd", reference:"5.4.4-14+deb7u13")) flag++;
if (deb_check(release:"7.0", prefix:"php5-gmp", reference:"5.4.4-14+deb7u13")) flag++;
if (deb_check(release:"7.0", prefix:"php5-imap", reference:"5.4.4-14+deb7u13")) flag++;
if (deb_check(release:"7.0", prefix:"php5-interbase", reference:"5.4.4-14+deb7u13")) flag++;
if (deb_check(release:"7.0", prefix:"php5-intl", reference:"5.4.4-14+deb7u13")) flag++;
if (deb_check(release:"7.0", prefix:"php5-ldap", reference:"5.4.4-14+deb7u13")) flag++;
if (deb_check(release:"7.0", prefix:"php5-mcrypt", reference:"5.4.4-14+deb7u13")) flag++;
if (deb_check(release:"7.0", prefix:"php5-mysql", reference:"5.4.4-14+deb7u13")) flag++;
if (deb_check(release:"7.0", prefix:"php5-mysqlnd", reference:"5.4.4-14+deb7u13")) flag++;
if (deb_check(release:"7.0", prefix:"php5-odbc", reference:"5.4.4-14+deb7u13")) flag++;
if (deb_check(release:"7.0", prefix:"php5-pgsql", reference:"5.4.4-14+deb7u13")) flag++;
if (deb_check(release:"7.0", prefix:"php5-pspell", reference:"5.4.4-14+deb7u13")) flag++;
if (deb_check(release:"7.0", prefix:"php5-recode", reference:"5.4.4-14+deb7u13")) flag++;
if (deb_check(release:"7.0", prefix:"php5-snmp", reference:"5.4.4-14+deb7u13")) flag++;
if (deb_check(release:"7.0", prefix:"php5-sqlite", reference:"5.4.4-14+deb7u13")) flag++;
if (deb_check(release:"7.0", prefix:"php5-sybase", reference:"5.4.4-14+deb7u13")) flag++;
if (deb_check(release:"7.0", prefix:"php5-tidy", reference:"5.4.4-14+deb7u13")) flag++;
if (deb_check(release:"7.0", prefix:"php5-xmlrpc", reference:"5.4.4-14+deb7u13")) flag++;
if (deb_check(release:"7.0", prefix:"php5-xsl", reference:"5.4.4-14+deb7u13")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:deb_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
