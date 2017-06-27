#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Debian Security Advisory DSA-1789. The text 
# itself is copyright (C) Software in the Public Interest, Inc.
#

include("compat.inc");

if (description)
{
  script_id(38691);
  script_version("$Revision: 1.13 $");
  script_cvs_date("$Date: 2016/12/06 20:12:51 $");

  script_cve_id("CVE-2008-2107", "CVE-2008-2108", "CVE-2008-5557", "CVE-2008-5624", "CVE-2008-5658", "CVE-2008-5814", "CVE-2009-0754", "CVE-2009-1271");
  script_bugtraq_id(29009, 32625, 32948, 33542);
  script_xref(name:"DSA", value:"1789");

  script_name(english:"Debian DSA-1789-1 : php5 - several vulnerabilities");
  script_summary(english:"Checks dpkg output for the updated package");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Debian host is missing a security-related update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Several remote vulnerabilities have been discovered in the PHP 5
hypertext preprocessor. The Common Vulnerabilities and Exposures
project identifies the following problems.

The following four vulnerabilities have already been fixed in the
stable (lenny) version of php5 prior to the release of lenny. This
update now addresses them for etch (oldstable) as well :

  - CVE-2008-2107 / CVE-2008-2108
    The GENERATE_SEED macro has several problems that make
    predicting generated random numbers easier, facilitating
    attacks against measures that use rand() or mt_rand() as
    part of a protection.

  - CVE-2008-5557
    A buffer overflow in the mbstring extension allows
    attackers to execute arbitrary code via a crafted string
    containing an HTML entity.

  - CVE-2008-5624
    The page_uid and page_gid variables are not correctly
    set, allowing use of some functionality intended to be
    restricted to root.

  - CVE-2008-5658
    Directory traversal vulnerability in the
    ZipArchive::extractTo function allows attackers to write
    arbitrary files via a ZIP file with a file whose name
    contains .. (dot dot) sequences.

This update also addresses the following three vulnerabilities for
both oldstable (etch) and stable (lenny) :

  - CVE-2008-5814
    Cross-site scripting (XSS) vulnerability, when
    display_errors is enabled, allows remote attackers to
    inject arbitrary web script or HTML.

  - CVE-2009-0754
    When running on Apache, PHP allows local users to modify
    behavior of other sites hosted on the same web server by
    modifying the mbstring.func_overload setting within
    .htaccess, which causes this setting to be applied to
    other virtual hosts on the same server. 

  - CVE-2009-1271
    The JSON_parser function allows a denial of service
    (segmentation fault) via a malformed string to the
    json_decode API function.

Furthermore, two updates originally scheduled for the next point
update for oldstable are included in the etch package :

  - Let PHP use the system timezone database instead of the
    embedded timezone database which is out of date.
  - From the source tarball, the unused 'dbase' module has
    been removed which contained licensing problems."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://bugs.debian.org/cgi-bin/bugreport.cgi?bug=507101"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://bugs.debian.org/cgi-bin/bugreport.cgi?bug=507857"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://bugs.debian.org/cgi-bin/bugreport.cgi?bug=508021"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://bugs.debian.org/cgi-bin/bugreport.cgi?bug=511493"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://bugs.debian.org/cgi-bin/bugreport.cgi?bug=523028"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://bugs.debian.org/cgi-bin/bugreport.cgi?bug=523049"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2008-2107"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2008-2108"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2008-5557"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2008-5624"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2008-5658"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2008-5814"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2009-0754"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2009-1271"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.debian.org/security/2009/dsa-1789"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"Upgrade the php5 package.

For the old stable distribution (etch), these problems have been fixed
in version 5.2.0+dfsg-8+etch15.


For the stable distribution (lenny), these problems have been fixed in
version 5.2.6.dfsg.1-1+lenny3."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_cwe_id(22, 79, 119, 134, 189, 264);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:php5");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:4.0");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:5.0");

  script_set_attribute(attribute:"patch_publication_date", value:"2009/05/04");
  script_set_attribute(attribute:"plugin_publication_date", value:"2009/05/06");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2009-2016 Tenable Network Security, Inc.");
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
if (deb_check(release:"4.0", prefix:"libapache-mod-php5", reference:"5.2.0+dfsg-8+etch15")) flag++;
if (deb_check(release:"4.0", prefix:"libapache2-mod-php5", reference:"5.2.0+dfsg-8+etch15")) flag++;
if (deb_check(release:"4.0", prefix:"php-pear", reference:"5.2.0+dfsg-8+etch15")) flag++;
if (deb_check(release:"4.0", prefix:"php5", reference:"5.2.0+dfsg-8+etch15")) flag++;
if (deb_check(release:"4.0", prefix:"php5-cgi", reference:"5.2.0+dfsg-8+etch15")) flag++;
if (deb_check(release:"4.0", prefix:"php5-cli", reference:"5.2.0+dfsg-8+etch15")) flag++;
if (deb_check(release:"4.0", prefix:"php5-common", reference:"5.2.0+dfsg-8+etch15")) flag++;
if (deb_check(release:"4.0", prefix:"php5-curl", reference:"5.2.0+dfsg-8+etch15")) flag++;
if (deb_check(release:"4.0", prefix:"php5-dev", reference:"5.2.0+dfsg-8+etch15")) flag++;
if (deb_check(release:"4.0", prefix:"php5-gd", reference:"5.2.0+dfsg-8+etch15")) flag++;
if (deb_check(release:"4.0", prefix:"php5-imap", reference:"5.2.0+dfsg-8+etch15")) flag++;
if (deb_check(release:"4.0", prefix:"php5-interbase", reference:"5.2.0+dfsg-8+etch15")) flag++;
if (deb_check(release:"4.0", prefix:"php5-ldap", reference:"5.2.0+dfsg-8+etch15")) flag++;
if (deb_check(release:"4.0", prefix:"php5-mcrypt", reference:"5.2.0+dfsg-8+etch15")) flag++;
if (deb_check(release:"4.0", prefix:"php5-mhash", reference:"5.2.0+dfsg-8+etch15")) flag++;
if (deb_check(release:"4.0", prefix:"php5-mysql", reference:"5.2.0+dfsg-8+etch15")) flag++;
if (deb_check(release:"4.0", prefix:"php5-odbc", reference:"5.2.0+dfsg-8+etch15")) flag++;
if (deb_check(release:"4.0", prefix:"php5-pgsql", reference:"5.2.0+dfsg-8+etch15")) flag++;
if (deb_check(release:"4.0", prefix:"php5-pspell", reference:"5.2.0+dfsg-8+etch15")) flag++;
if (deb_check(release:"4.0", prefix:"php5-recode", reference:"5.2.0+dfsg-8+etch15")) flag++;
if (deb_check(release:"4.0", prefix:"php5-snmp", reference:"5.2.0+dfsg-8+etch15")) flag++;
if (deb_check(release:"4.0", prefix:"php5-sqlite", reference:"5.2.0+dfsg-8+etch15")) flag++;
if (deb_check(release:"4.0", prefix:"php5-sybase", reference:"5.2.0+dfsg-8+etch15")) flag++;
if (deb_check(release:"4.0", prefix:"php5-tidy", reference:"5.2.0+dfsg-8+etch15")) flag++;
if (deb_check(release:"4.0", prefix:"php5-xmlrpc", reference:"5.2.0+dfsg-8+etch15")) flag++;
if (deb_check(release:"4.0", prefix:"php5-xsl", reference:"5.2.0+dfsg-8+etch15")) flag++;
if (deb_check(release:"5.0", prefix:"libapache2-mod-php5", reference:"5.2.6.dfsg.1-1+lenny3")) flag++;
if (deb_check(release:"5.0", prefix:"libapache2-mod-php5filter", reference:"5.2.6.dfsg.1-1+lenny3")) flag++;
if (deb_check(release:"5.0", prefix:"php-pear", reference:"5.2.6.dfsg.1-1+lenny3")) flag++;
if (deb_check(release:"5.0", prefix:"php5", reference:"5.2.6.dfsg.1-1+lenny3")) flag++;
if (deb_check(release:"5.0", prefix:"php5-cgi", reference:"5.2.6.dfsg.1-1+lenny3")) flag++;
if (deb_check(release:"5.0", prefix:"php5-cli", reference:"5.2.6.dfsg.1-1+lenny3")) flag++;
if (deb_check(release:"5.0", prefix:"php5-common", reference:"5.2.6.dfsg.1-1+lenny3")) flag++;
if (deb_check(release:"5.0", prefix:"php5-curl", reference:"5.2.6.dfsg.1-1+lenny3")) flag++;
if (deb_check(release:"5.0", prefix:"php5-dbg", reference:"5.2.6.dfsg.1-1+lenny3")) flag++;
if (deb_check(release:"5.0", prefix:"php5-dev", reference:"5.2.6.dfsg.1-1+lenny3")) flag++;
if (deb_check(release:"5.0", prefix:"php5-gd", reference:"5.2.6.dfsg.1-1+lenny3")) flag++;
if (deb_check(release:"5.0", prefix:"php5-gmp", reference:"5.2.6.dfsg.1-1+lenny3")) flag++;
if (deb_check(release:"5.0", prefix:"php5-imap", reference:"5.2.6.dfsg.1-1+lenny3")) flag++;
if (deb_check(release:"5.0", prefix:"php5-interbase", reference:"5.2.6.dfsg.1-1+lenny3")) flag++;
if (deb_check(release:"5.0", prefix:"php5-ldap", reference:"5.2.6.dfsg.1-1+lenny3")) flag++;
if (deb_check(release:"5.0", prefix:"php5-mcrypt", reference:"5.2.6.dfsg.1-1+lenny3")) flag++;
if (deb_check(release:"5.0", prefix:"php5-mhash", reference:"5.2.6.dfsg.1-1+lenny3")) flag++;
if (deb_check(release:"5.0", prefix:"php5-mysql", reference:"5.2.6.dfsg.1-1+lenny3")) flag++;
if (deb_check(release:"5.0", prefix:"php5-odbc", reference:"5.2.6.dfsg.1-1+lenny3")) flag++;
if (deb_check(release:"5.0", prefix:"php5-pgsql", reference:"5.2.6.dfsg.1-1+lenny3")) flag++;
if (deb_check(release:"5.0", prefix:"php5-pspell", reference:"5.2.6.dfsg.1-1+lenny3")) flag++;
if (deb_check(release:"5.0", prefix:"php5-recode", reference:"5.2.6.dfsg.1-1+lenny3")) flag++;
if (deb_check(release:"5.0", prefix:"php5-snmp", reference:"5.2.6.dfsg.1-1+lenny3")) flag++;
if (deb_check(release:"5.0", prefix:"php5-sqlite", reference:"5.2.6.dfsg.1-1+lenny3")) flag++;
if (deb_check(release:"5.0", prefix:"php5-sybase", reference:"5.2.6.dfsg.1-1+lenny3")) flag++;
if (deb_check(release:"5.0", prefix:"php5-tidy", reference:"5.2.6.dfsg.1-1+lenny3")) flag++;
if (deb_check(release:"5.0", prefix:"php5-xmlrpc", reference:"5.2.6.dfsg.1-1+lenny3")) flag++;
if (deb_check(release:"5.0", prefix:"php5-xsl", reference:"5.2.6.dfsg.1-1+lenny3")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:deb_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
