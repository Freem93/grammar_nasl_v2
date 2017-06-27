#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Debian Security Advisory DSA-1283. The text 
# itself is copyright (C) Software in the Public Interest, Inc.
#

if (NASL_LEVEL < 3000) exit(0);

include("compat.inc");

if (description)
{
  script_id(25100);
  script_version("$Revision: 1.17 $");
  script_cvs_date("$Date: 2014/05/03 11:14:58 $");

  script_cve_id("CVE-2007-1286", "CVE-2007-1375", "CVE-2007-1376", "CVE-2007-1380", "CVE-2007-1453", "CVE-2007-1454", "CVE-2007-1521", "CVE-2007-1583", "CVE-2007-1700", "CVE-2007-1711", "CVE-2007-1718", "CVE-2007-1777", "CVE-2007-1824", "CVE-2007-1887", "CVE-2007-1889", "CVE-2007-1900");
  script_osvdb_id(32770, 32771, 32776, 32780, 32781, 33932, 33933, 33936, 33940, 33944, 33946, 33948, 33949, 33958, 33959, 33961, 33962);
  script_xref(name:"DSA", value:"1283");

  script_name(english:"Debian DSA-1283-1 : php5 - several vulnerabilities");
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

  - CVE-2007-1286
    Stefan Esser discovered an overflow in the object
    reference handling code of the unserialize() function,
    which allows the execution of arbitrary code if
    malformed input is passed from an application.

  - CVE-2007-1375
    Stefan Esser discovered that an integer overflow in the
    substr_compare() function allows information disclosure
    of heap memory.

  - CVE-2007-1376
    Stefan Esser discovered that insufficient validation of
    shared memory functions allows the disclosure of heap
    memory.

  - CVE-2007-1380
    Stefan Esser discovered that the session handler
    performs insufficient validation of variable name length
    values, which allows information disclosure through a
    heap information leak.

  - CVE-2007-1453
    Stefan Esser discovered that the filtering framework
    performs insufficient input validation, which allows the
    execution of arbitrary code through a buffer underflow.

  - CVE-2007-1454
    Stefan Esser discovered that the filtering framework can
    be bypassed with a special whitespace character.

  - CVE-2007-1521
    Stefan Esser discovered a double free vulnerability in
    the session_regenerate_id() function, which allows the
    execution of arbitrary code.

  - CVE-2007-1583
    Stefan Esser discovered that a programming error in the
    mb_parse_str() function allows the activation of
    'register_globals'.

  - CVE-2007-1700
    Stefan Esser discovered that the session extension
    incorrectly maintains the reference count of session
    variables, which allows the execution of arbitrary code.

  - CVE-2007-1711
    Stefan Esser discovered a double free vulnerability in
    the session management code, which allows the execution
    of arbitrary code.

  - CVE-2007-1718
    Stefan Esser discovered that the mail() function
    performs insufficient validation of folded mail headers,
    which allows mail header injection.

  - CVE-2007-1777
    Stefan Esser discovered that the extension to handle ZIP
    archives performs insufficient length checks, which
    allows the execution of arbitrary code.

  - CVE-2007-1824
    Stefan Esser discovered an off-by-one error in the
    filtering framework, which allows the execution of
    arbitrary code.

  - CVE-2007-1887
    Stefan Esser discovered that a buffer overflow in the
    sqlite extension allows the execution of arbitrary code.

  - CVE-2007-1889
    Stefan Esser discovered that the PHP memory manager
    performs an incorrect type cast, which allows the
    execution of arbitrary code through buffer overflows.

  - CVE-2007-1900
    Stefan Esser discovered that incorrect validation in the
    email filter extension allows the injection of mail
    headers.

The oldstable distribution (sarge) doesn't include php5."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2007-1286"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2007-1375"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2007-1376"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2007-1380"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2007-1453"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2007-1454"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2007-1521"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2007-1583"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2007-1700"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2007-1711"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2007-1718"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2007-1777"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2007-1824"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2007-1887"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2007-1889"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2007-1900"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.debian.org/security/2007/dsa-1283"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"Upgrade the PHP packages. Packages for the arm, hppa, mips and mipsel
architectures are not yet available. They will be provided later.

For the stable distribution (etch) these problems have been fixed in
version 5.2.0-8+etch3."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:C/A:N");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"metasploit_name", value:'PHP 4 unserialize() ZVAL Reference Counter Overflow (Cookie)');
  script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:php5");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:4.0");

  script_set_attribute(attribute:"patch_publication_date", value:"2007/04/29");
  script_set_attribute(attribute:"plugin_publication_date", value:"2007/04/30");
  script_set_attribute(attribute:"vuln_publication_date", value:"2007/02/09");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2007-2014 Tenable Network Security, Inc.");
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
if (deb_check(release:"4.0", prefix:"libapache-mod-php5", reference:"5.2.0-8+etch3")) flag++;
if (deb_check(release:"4.0", prefix:"libapache2-mod-php5", reference:"5.2.0-8+etch3")) flag++;
if (deb_check(release:"4.0", prefix:"php-pear", reference:"5.2.0-8+etch3")) flag++;
if (deb_check(release:"4.0", prefix:"php5", reference:"5.2.0-8+etch3")) flag++;
if (deb_check(release:"4.0", prefix:"php5-cgi", reference:"5.2.0-8+etch3")) flag++;
if (deb_check(release:"4.0", prefix:"php5-cli", reference:"5.2.0-8+etch3")) flag++;
if (deb_check(release:"4.0", prefix:"php5-common", reference:"5.2.0-8+etch3")) flag++;
if (deb_check(release:"4.0", prefix:"php5-curl", reference:"5.2.0-8+etch3")) flag++;
if (deb_check(release:"4.0", prefix:"php5-dev", reference:"5.2.0-8+etch3")) flag++;
if (deb_check(release:"4.0", prefix:"php5-gd", reference:"5.2.0-8+etch3")) flag++;
if (deb_check(release:"4.0", prefix:"php5-imap", reference:"5.2.0-8+etch3")) flag++;
if (deb_check(release:"4.0", prefix:"php5-interbase", reference:"5.2.0-8+etch3")) flag++;
if (deb_check(release:"4.0", prefix:"php5-ldap", reference:"5.2.0-8+etch3")) flag++;
if (deb_check(release:"4.0", prefix:"php5-mcrypt", reference:"5.2.0-8+etch3")) flag++;
if (deb_check(release:"4.0", prefix:"php5-mhash", reference:"5.2.0-8+etch3")) flag++;
if (deb_check(release:"4.0", prefix:"php5-mysql", reference:"5.2.0-8+etch3")) flag++;
if (deb_check(release:"4.0", prefix:"php5-odbc", reference:"5.2.0-8+etch3")) flag++;
if (deb_check(release:"4.0", prefix:"php5-pgsql", reference:"5.2.0-8+etch3")) flag++;
if (deb_check(release:"4.0", prefix:"php5-pspell", reference:"5.2.0-8+etch3")) flag++;
if (deb_check(release:"4.0", prefix:"php5-recode", reference:"5.2.0-8+etch3")) flag++;
if (deb_check(release:"4.0", prefix:"php5-snmp", reference:"5.2.0-8+etch3")) flag++;
if (deb_check(release:"4.0", prefix:"php5-sqlite", reference:"5.2.0-8+etch3")) flag++;
if (deb_check(release:"4.0", prefix:"php5-sybase", reference:"5.2.0-8+etch3")) flag++;
if (deb_check(release:"4.0", prefix:"php5-tidy", reference:"5.2.0-8+etch3")) flag++;
if (deb_check(release:"4.0", prefix:"php5-xmlrpc", reference:"5.2.0-8+etch3")) flag++;
if (deb_check(release:"4.0", prefix:"php5-xsl", reference:"5.2.0-8+etch3")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:deb_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
