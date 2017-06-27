#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Debian Security Advisory DSA-1282. The text 
# itself is copyright (C) Software in the Public Interest, Inc.
#

include("compat.inc");

if (description)
{
  script_id(25099);
  script_version("$Revision: 1.15 $");
  script_cvs_date("$Date: 2014/05/03 11:14:58 $");

  script_cve_id("CVE-2007-1286", "CVE-2007-1380", "CVE-2007-1521", "CVE-2007-1711", "CVE-2007-1718", "CVE-2007-1777");
  script_osvdb_id(32770, 32771, 32776, 33936, 33946, 33948, 33949);
  script_xref(name:"DSA", value:"1282");

  script_name(english:"Debian DSA-1282-1 : php4 - several vulnerabilities");
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

  - CVE-2007-1380
    Stefan Esser discovered that the session handler
    performs insufficient validation of variable name length
    values, which allows information disclosure through a
    heap information leak.

  - CVE-2007-1521
    Stefan Esser discovered a double free vulnerability in
    the session_regenerate_id() function, which allows the
    execution of arbitrary code.

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
    allows the execution of arbitrary code."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2007-1286"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2007-1380"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2007-1521"
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
    value:"http://www.debian.org/security/2007/dsa-1282"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"Upgrade the PHP packages. Packages for the arm, m68k, mips and mipsel
architectures are not yet available. They will be provided later.

For the oldstable distribution (sarge) these problems have been fixed
in version 4.3.10-20.

For the stable distribution (etch) these problems have been fixed in
version 4.4.4-8+etch2."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:C/A:N");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"metasploit_name", value:'PHP 4 unserialize() ZVAL Reference Counter Overflow (Cookie)');
  script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:php4");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:3.1");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:4.0");

  script_set_attribute(attribute:"patch_publication_date", value:"2007/04/26");
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
if (deb_check(release:"3.1", prefix:"libapache-mod-php4", reference:"4.3.10-20")) flag++;
if (deb_check(release:"3.1", prefix:"libapache2-mod-php4", reference:"4.3.10-20")) flag++;
if (deb_check(release:"3.1", prefix:"php4", reference:"4.3.10-20")) flag++;
if (deb_check(release:"3.1", prefix:"php4-cgi", reference:"4.3.10-20")) flag++;
if (deb_check(release:"3.1", prefix:"php4-cli", reference:"4.3.10-20")) flag++;
if (deb_check(release:"3.1", prefix:"php4-common", reference:"4.3.10-20")) flag++;
if (deb_check(release:"3.1", prefix:"php4-curl", reference:"4.3.10-20")) flag++;
if (deb_check(release:"3.1", prefix:"php4-dev", reference:"4.3.10-20")) flag++;
if (deb_check(release:"3.1", prefix:"php4-domxml", reference:"4.3.10-20")) flag++;
if (deb_check(release:"3.1", prefix:"php4-gd", reference:"4.3.10-20")) flag++;
if (deb_check(release:"3.1", prefix:"php4-imap", reference:"4.3.10-20")) flag++;
if (deb_check(release:"3.1", prefix:"php4-ldap", reference:"4.3.10-20")) flag++;
if (deb_check(release:"3.1", prefix:"php4-mcal", reference:"4.3.10-20")) flag++;
if (deb_check(release:"3.1", prefix:"php4-mhash", reference:"4.3.10-20")) flag++;
if (deb_check(release:"3.1", prefix:"php4-mysql", reference:"4.3.10-20")) flag++;
if (deb_check(release:"3.1", prefix:"php4-odbc", reference:"4.3.10-20")) flag++;
if (deb_check(release:"3.1", prefix:"php4-pear", reference:"4.3.10-20")) flag++;
if (deb_check(release:"3.1", prefix:"php4-recode", reference:"4.3.10-20")) flag++;
if (deb_check(release:"3.1", prefix:"php4-snmp", reference:"4.3.10-20")) flag++;
if (deb_check(release:"3.1", prefix:"php4-sybase", reference:"4.3.10-20")) flag++;
if (deb_check(release:"3.1", prefix:"php4-xslt", reference:"4.3.10-20")) flag++;
if (deb_check(release:"4.0", prefix:"libapache-mod-php4", reference:"4.4.4-8+etch2")) flag++;
if (deb_check(release:"4.0", prefix:"libapache2-mod-php4", reference:"4.4.4-8+etch2")) flag++;
if (deb_check(release:"4.0", prefix:"php4", reference:"4.4.4-8+etch2")) flag++;
if (deb_check(release:"4.0", prefix:"php4-cgi", reference:"4.4.4-8+etch2")) flag++;
if (deb_check(release:"4.0", prefix:"php4-cli", reference:"4.4.4-8+etch2")) flag++;
if (deb_check(release:"4.0", prefix:"php4-common", reference:"4.4.4-8+etch2")) flag++;
if (deb_check(release:"4.0", prefix:"php4-curl", reference:"4.4.4-8+etch2")) flag++;
if (deb_check(release:"4.0", prefix:"php4-dev", reference:"4.4.4-8+etch2")) flag++;
if (deb_check(release:"4.0", prefix:"php4-domxml", reference:"4.4.4-8+etch2")) flag++;
if (deb_check(release:"4.0", prefix:"php4-gd", reference:"4.4.4-8+etch2")) flag++;
if (deb_check(release:"4.0", prefix:"php4-imap", reference:"4.4.4-8+etch2")) flag++;
if (deb_check(release:"4.0", prefix:"php4-interbase", reference:"4.4.4-8+etch2")) flag++;
if (deb_check(release:"4.0", prefix:"php4-ldap", reference:"4.4.4-8+etch2")) flag++;
if (deb_check(release:"4.0", prefix:"php4-mcal", reference:"4.4.4-8+etch2")) flag++;
if (deb_check(release:"4.0", prefix:"php4-mcrypt", reference:"4.4.4-8+etch2")) flag++;
if (deb_check(release:"4.0", prefix:"php4-mhash", reference:"4.4.4-8+etch2")) flag++;
if (deb_check(release:"4.0", prefix:"php4-mysql", reference:"4.4.4-8+etch2")) flag++;
if (deb_check(release:"4.0", prefix:"php4-odbc", reference:"4.4.4-8+etch2")) flag++;
if (deb_check(release:"4.0", prefix:"php4-pear", reference:"4.4.4-8+etch2")) flag++;
if (deb_check(release:"4.0", prefix:"php4-pgsql", reference:"4.4.4-8+etch2")) flag++;
if (deb_check(release:"4.0", prefix:"php4-pspell", reference:"4.4.4-8+etch2")) flag++;
if (deb_check(release:"4.0", prefix:"php4-recode", reference:"4.4.4-8+etch2")) flag++;
if (deb_check(release:"4.0", prefix:"php4-snmp", reference:"4.4.4-8+etch2")) flag++;
if (deb_check(release:"4.0", prefix:"php4-sybase", reference:"4.4.4-8+etch2")) flag++;
if (deb_check(release:"4.0", prefix:"php4-xslt", reference:"4.4.4-8+etch2")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:deb_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
