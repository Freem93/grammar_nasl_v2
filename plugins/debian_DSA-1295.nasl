#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Debian Security Advisory DSA-1295. The text 
# itself is copyright (C) Software in the Public Interest, Inc.
#

include("compat.inc");

if (description)
{
  script_id(25299);
  script_version("$Revision: 1.13 $");
  script_cvs_date("$Date: 2016/12/06 20:12:50 $");

  script_cve_id("CVE-2007-2509", "CVE-2007-2510");
  script_xref(name:"DSA", value:"1295");

  script_name(english:"Debian DSA-1295-1 : php5 - several vulnerabilities");
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

  - CVE-2007-2509
    It was discovered that missing input sanitising inside
    the ftp extension permits an attacker to execute
    arbitrary FTP commands. This requires the attacker to
    already have access to the FTP server.

  - CVE-2007-2510
    It was discovered that a buffer overflow in the SOAP
    extension permits the execution of arbitrary code.

The oldstable distribution (sarge) doesn't include php5."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2007-2509"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2007-2510"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.debian.org/security/2007/dsa-1295"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"Upgrade the PHP packages. Packages for the Sparc architectures are not
yet available, due to problems on the build host. They will be
provided later.

For the stable distribution (etch) these problems have been fixed in
version 5.2.0-8+etch4."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:H/Au:N/C:P/I:P/A:P");
  script_cwe_id(20, 119);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:php5");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:4.0");

  script_set_attribute(attribute:"patch_publication_date", value:"2007/05/19");
  script_set_attribute(attribute:"plugin_publication_date", value:"2007/05/25");
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
if (deb_check(release:"4.0", prefix:"libapache-mod-php5", reference:"5.2.0-8+etch4")) flag++;
if (deb_check(release:"4.0", prefix:"libapache2-mod-php5", reference:"5.2.0-8+etch4")) flag++;
if (deb_check(release:"4.0", prefix:"php-pear", reference:"5.2.0-8+etch4")) flag++;
if (deb_check(release:"4.0", prefix:"php5", reference:"5.2.0-8+etch4")) flag++;
if (deb_check(release:"4.0", prefix:"php5-cgi", reference:"5.2.0-8+etch4")) flag++;
if (deb_check(release:"4.0", prefix:"php5-cli", reference:"5.2.0-8+etch4")) flag++;
if (deb_check(release:"4.0", prefix:"php5-common", reference:"5.2.0-8+etch4")) flag++;
if (deb_check(release:"4.0", prefix:"php5-curl", reference:"5.2.0-8+etch4")) flag++;
if (deb_check(release:"4.0", prefix:"php5-dev", reference:"5.2.0-8+etch4")) flag++;
if (deb_check(release:"4.0", prefix:"php5-gd", reference:"5.2.0-8+etch4")) flag++;
if (deb_check(release:"4.0", prefix:"php5-imap", reference:"5.2.0-8+etch4")) flag++;
if (deb_check(release:"4.0", prefix:"php5-interbase", reference:"5.2.0-8+etch4")) flag++;
if (deb_check(release:"4.0", prefix:"php5-ldap", reference:"5.2.0-8+etch4")) flag++;
if (deb_check(release:"4.0", prefix:"php5-mcrypt", reference:"5.2.0-8+etch4")) flag++;
if (deb_check(release:"4.0", prefix:"php5-mhash", reference:"5.2.0-8+etch4")) flag++;
if (deb_check(release:"4.0", prefix:"php5-mysql", reference:"5.2.0-8+etch4")) flag++;
if (deb_check(release:"4.0", prefix:"php5-odbc", reference:"5.2.0-8+etch4")) flag++;
if (deb_check(release:"4.0", prefix:"php5-pgsql", reference:"5.2.0-8+etch4")) flag++;
if (deb_check(release:"4.0", prefix:"php5-pspell", reference:"5.2.0-8+etch4")) flag++;
if (deb_check(release:"4.0", prefix:"php5-recode", reference:"5.2.0-8+etch4")) flag++;
if (deb_check(release:"4.0", prefix:"php5-snmp", reference:"5.2.0-8+etch4")) flag++;
if (deb_check(release:"4.0", prefix:"php5-sqlite", reference:"5.2.0-8+etch4")) flag++;
if (deb_check(release:"4.0", prefix:"php5-sybase", reference:"5.2.0-8+etch4")) flag++;
if (deb_check(release:"4.0", prefix:"php5-tidy", reference:"5.2.0-8+etch4")) flag++;
if (deb_check(release:"4.0", prefix:"php5-xmlrpc", reference:"5.2.0-8+etch4")) flag++;
if (deb_check(release:"4.0", prefix:"php5-xsl", reference:"5.2.0-8+etch4")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:deb_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
