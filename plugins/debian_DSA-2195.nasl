#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Debian Security Advisory DSA-2195. The text 
# itself is copyright (C) Software in the Public Interest, Inc.
#

include("compat.inc");

if (description)
{
  script_id(52719);
  script_version("$Revision: 1.9 $");
  script_cvs_date("$Date: 2016/05/05 14:58:41 $");

  script_cve_id("CVE-2010-3709", "CVE-2010-3710", "CVE-2010-3870", "CVE-2010-4150", "CVE-2011-0441");
  script_bugtraq_id(43926, 44605, 44718, 44980);
  script_osvdb_id(68597, 69109, 69230, 69660);
  script_xref(name:"DSA", value:"2195");

  script_name(english:"Debian DSA-2195-1 : php5 - several vulnerabilities");
  script_summary(english:"Checks dpkg output for the updated package");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Debian host is missing a security-related update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Stephane Chazelas discovered that the cronjob of the PHP 5 package in
Debian suffers from a race condition which might be used to remove
arbitrary files from a system (CVE-2011-0441 ).

When upgrading your php5-common package take special care to acceptthe
changes to the /etc/cron.d/php5 file. Ignoring them would leave the
system vulnerable."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2011-0441"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2010-3709"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2010-3710"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2010-3870"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2010-4150"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://packages.debian.org/source/squeeze/php5"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.debian.org/security/2011/dsa-2195"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"Upgrade the php5 packages.

For the oldstable distribution (lenny), this problem has been fixed in
version 5.2.6.dfsg.1-1+lenny10.

For the stable distribution (squeeze), this problem has been fixed in
version 5.3.3-7+squeeze1.

Additionally, the following vulnerabilities have also been fixed in
the oldstable distribution (lenny) :

  - CVE-2010-3709
    Maksymilian Arciemowicz discovered that the ZipArchive
    class may dereference a NULL pointer when extracting
    comments from a ZIP archive, leading to application
    crash and possible denial of service.

  - CVE-2010-3710

    Stefan Neufeind discovered that the
    FILTER_VALIDATE_EMAIL filter does not correctly handle
    long, to be validated, strings. Such crafted strings may
    lead to denial of service because of high memory
    consumption and application crash.

  - CVE-2010-3870

    It was discovered that PHP does not correctly handle
    certain UTF-8 sequences and may be used to bypass XSS
    protections.

  - CVE-2010-4150

    Mateusz Kocielski discovered that the IMAP extension may
    try to free already freed memory when processing user
    credentials, leading to application crash and possibly
    arbitrary code execution."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:php5");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:5.0");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:6.0");

  script_set_attribute(attribute:"patch_publication_date", value:"2011/03/19");
  script_set_attribute(attribute:"plugin_publication_date", value:"2011/03/21");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2011-2016 Tenable Network Security, Inc.");
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
if (deb_check(release:"5.0", prefix:"php5", reference:"5.2.6.dfsg.1-1+lenny10")) flag++;
if (deb_check(release:"6.0", prefix:"libapache2-mod-php5", reference:"5.3.3-7+squeeze1")) flag++;
if (deb_check(release:"6.0", prefix:"libapache2-mod-php5filter", reference:"5.3.3-7+squeeze1")) flag++;
if (deb_check(release:"6.0", prefix:"php-pear", reference:"5.3.3-7+squeeze1")) flag++;
if (deb_check(release:"6.0", prefix:"php5", reference:"5.3.3-7+squeeze1")) flag++;
if (deb_check(release:"6.0", prefix:"php5-cgi", reference:"5.3.3-7+squeeze1")) flag++;
if (deb_check(release:"6.0", prefix:"php5-cli", reference:"5.3.3-7+squeeze1")) flag++;
if (deb_check(release:"6.0", prefix:"php5-common", reference:"5.3.3-7+squeeze1")) flag++;
if (deb_check(release:"6.0", prefix:"php5-curl", reference:"5.3.3-7+squeeze1")) flag++;
if (deb_check(release:"6.0", prefix:"php5-dbg", reference:"5.3.3-7+squeeze1")) flag++;
if (deb_check(release:"6.0", prefix:"php5-dev", reference:"5.3.3-7+squeeze1")) flag++;
if (deb_check(release:"6.0", prefix:"php5-enchant", reference:"5.3.3-7+squeeze1")) flag++;
if (deb_check(release:"6.0", prefix:"php5-gd", reference:"5.3.3-7+squeeze1")) flag++;
if (deb_check(release:"6.0", prefix:"php5-gmp", reference:"5.3.3-7+squeeze1")) flag++;
if (deb_check(release:"6.0", prefix:"php5-imap", reference:"5.3.3-7+squeeze1")) flag++;
if (deb_check(release:"6.0", prefix:"php5-interbase", reference:"5.3.3-7+squeeze1")) flag++;
if (deb_check(release:"6.0", prefix:"php5-intl", reference:"5.3.3-7+squeeze1")) flag++;
if (deb_check(release:"6.0", prefix:"php5-ldap", reference:"5.3.3-7+squeeze1")) flag++;
if (deb_check(release:"6.0", prefix:"php5-mcrypt", reference:"5.3.3-7+squeeze1")) flag++;
if (deb_check(release:"6.0", prefix:"php5-mysql", reference:"5.3.3-7+squeeze1")) flag++;
if (deb_check(release:"6.0", prefix:"php5-odbc", reference:"5.3.3-7+squeeze1")) flag++;
if (deb_check(release:"6.0", prefix:"php5-pgsql", reference:"5.3.3-7+squeeze1")) flag++;
if (deb_check(release:"6.0", prefix:"php5-pspell", reference:"5.3.3-7+squeeze1")) flag++;
if (deb_check(release:"6.0", prefix:"php5-recode", reference:"5.3.3-7+squeeze1")) flag++;
if (deb_check(release:"6.0", prefix:"php5-snmp", reference:"5.3.3-7+squeeze1")) flag++;
if (deb_check(release:"6.0", prefix:"php5-sqlite", reference:"5.3.3-7+squeeze1")) flag++;
if (deb_check(release:"6.0", prefix:"php5-sybase", reference:"5.3.3-7+squeeze1")) flag++;
if (deb_check(release:"6.0", prefix:"php5-tidy", reference:"5.3.3-7+squeeze1")) flag++;
if (deb_check(release:"6.0", prefix:"php5-xmlrpc", reference:"5.3.3-7+squeeze1")) flag++;
if (deb_check(release:"6.0", prefix:"php5-xsl", reference:"5.3.3-7+squeeze1")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:deb_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
