#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Debian Security Advisory DSA-1264. The text 
# itself is copyright (C) Software in the Public Interest, Inc.
#

if (NASL_LEVEL < 3000) exit(0);

include("compat.inc");

if (description)
{
  script_id(24793);
  script_version("$Revision: 1.16 $");
  script_cvs_date("$Date: 2016/12/06 20:12:50 $");

  script_cve_id("CVE-2007-0906", "CVE-2007-0907", "CVE-2007-0908", "CVE-2007-0909", "CVE-2007-0910", "CVE-2007-0988");
  script_osvdb_id(23767, 32762, 32763, 32764, 32765, 32766, 32767, 32768, 34706, 34707, 34708, 34709, 34710, 34711, 34712, 34713, 34714, 34715);
  script_xref(name:"DSA", value:"1264");

  script_name(english:"Debian DSA-1264-1 : php4 - several vulnerabilities");
  script_summary(english:"Checks dpkg output for the updated package");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Debian host is missing a security-related update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Several remote vulnerabilities have been discovered in PHP, a
server-side, HTML-embedded scripting language, which may lead to the
execution of arbitrary code. The Common Vulnerabilities and Exposures
project identifies the following problems :

  - CVE-2007-0906
    It was discovered that an integer overflow in the
    str_replace() function could lead to the execution of
    arbitrary code.

  - CVE-2007-0907
    It was discovered that a buffer underflow in the
    sapi_header_op() function could crash the PHP
    interpreter.

  - CVE-2007-0908
    Stefan Esser discovered that a programming error in the
    wddx extension allows information disclosure.

  - CVE-2007-0909
    It was discovered that a format string vulnerability in
    the odbc_result_all() functions allows the execution of
    arbitrary code.

  - CVE-2007-0910
    It was discovered that super-global variables could be
    overwritten with session data.

  - CVE-2007-0988
    Stefan Esser discovered that the zend_hash_init()
    function could be tricked into an endless loop, allowing
    denial of service through resource consumption until a
    timeout is triggered."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2007-0906"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2007-0907"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2007-0908"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2007-0909"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2007-0910"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2007-0988"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.debian.org/security/2007/dsa-1264"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"Upgrade the php4 packages.

For the stable distribution (sarge) these problems have been fixed in
version 4:4.3.10-19."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_cwe_id(20, 399);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:php4");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:3.1");

  script_set_attribute(attribute:"patch_publication_date", value:"2007/03/07");
  script_set_attribute(attribute:"plugin_publication_date", value:"2007/03/12");
  script_set_attribute(attribute:"vuln_publication_date", value:"2006/02/25");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2007-2016 Tenable Network Security, Inc.");
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
if (deb_check(release:"3.1", prefix:"libapache-mod-php4", reference:"4:4.3.10-19")) flag++;
if (deb_check(release:"3.1", prefix:"libapache2-mod-php4", reference:"4:4.3.10-19")) flag++;
if (deb_check(release:"3.1", prefix:"php4", reference:"4:4.3.10-19")) flag++;
if (deb_check(release:"3.1", prefix:"php4-cgi", reference:"4:4.3.10-19")) flag++;
if (deb_check(release:"3.1", prefix:"php4-cli", reference:"4:4.3.10-19")) flag++;
if (deb_check(release:"3.1", prefix:"php4-common", reference:"4:4.3.10-19")) flag++;
if (deb_check(release:"3.1", prefix:"php4-curl", reference:"4:4.3.10-19")) flag++;
if (deb_check(release:"3.1", prefix:"php4-dev", reference:"4:4.3.10-19")) flag++;
if (deb_check(release:"3.1", prefix:"php4-domxml", reference:"4:4.3.10-19")) flag++;
if (deb_check(release:"3.1", prefix:"php4-gd", reference:"4:4.3.10-19")) flag++;
if (deb_check(release:"3.1", prefix:"php4-imap", reference:"4:4.3.10-19")) flag++;
if (deb_check(release:"3.1", prefix:"php4-ldap", reference:"4:4.3.10-19")) flag++;
if (deb_check(release:"3.1", prefix:"php4-mcal", reference:"4:4.3.10-19")) flag++;
if (deb_check(release:"3.1", prefix:"php4-mhash", reference:"4:4.3.10-19")) flag++;
if (deb_check(release:"3.1", prefix:"php4-mysql", reference:"4:4.3.10-19")) flag++;
if (deb_check(release:"3.1", prefix:"php4-odbc", reference:"4:4.3.10-19")) flag++;
if (deb_check(release:"3.1", prefix:"php4-pear", reference:"4:4.3.10-19")) flag++;
if (deb_check(release:"3.1", prefix:"php4-recode", reference:"4:4.3.10-19")) flag++;
if (deb_check(release:"3.1", prefix:"php4-snmp", reference:"4:4.3.10-19")) flag++;
if (deb_check(release:"3.1", prefix:"php4-sybase", reference:"4:4.3.10-19")) flag++;
if (deb_check(release:"3.1", prefix:"php4-xslt", reference:"4:4.3.10-19")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:deb_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
