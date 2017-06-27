#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Debian Security Advisory DSA-2001. The text 
# itself is copyright (C) Software in the Public Interest, Inc.
#

include("compat.inc");

if (description)
{
  script_id(44865);
  script_version("$Revision: 1.9 $");
  script_cvs_date("$Date: 2016/05/26 15:53:37 $");

  script_cve_id("CVE-2009-4142", "CVE-2009-4143");
  script_bugtraq_id(37390);
  script_xref(name:"DSA", value:"2001");

  script_name(english:"Debian DSA-2001-1 : php5 - multiple vulnerabilities");
  script_summary(english:"Checks dpkg output for the updated package");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Debian host is missing a security-related update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Several remote vulnerabilities have been discovered in PHP 5, an
hypertext preprocessor. The Common Vulnerabilities and Exposures
project identifies the following problems :

  - CVE-2009-4142
    The htmlspecialchars function does not properly handle
    invalid multi-byte sequences.

  - CVE-2009-4143
    Memory corruption via session interruption.

In the stable distribution (lenny), this update also includes bug
fixes (bug #529278, #556459, #565387, #523073) that were to be
included in a stable point release as version 5.2.6.dfsg.1-1+lenny5."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2009-4142"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2009-4143"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.debian.org/security/2010/dsa-2001"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"Upgrade the php5 packages.

For the stable distribution (lenny), these problems have been fixed in
version 5.2.6.dfsg.1-1+lenny6."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_cwe_id(79);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:php5");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:5.0");

  script_set_attribute(attribute:"patch_publication_date", value:"2010/02/19");
  script_set_attribute(attribute:"plugin_publication_date", value:"2010/02/24");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2010-2016 Tenable Network Security, Inc.");
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
if (deb_check(release:"5.0", prefix:"libapache2-mod-php5", reference:"5.2.6.dfsg.1-1+lenny6")) flag++;
if (deb_check(release:"5.0", prefix:"libapache2-mod-php5filter", reference:"5.2.6.dfsg.1-1+lenny6")) flag++;
if (deb_check(release:"5.0", prefix:"php-pear", reference:"5.2.6.dfsg.1-1+lenny6")) flag++;
if (deb_check(release:"5.0", prefix:"php5", reference:"5.2.6.dfsg.1-1+lenny6")) flag++;
if (deb_check(release:"5.0", prefix:"php5-cgi", reference:"5.2.6.dfsg.1-1+lenny6")) flag++;
if (deb_check(release:"5.0", prefix:"php5-cli", reference:"5.2.6.dfsg.1-1+lenny6")) flag++;
if (deb_check(release:"5.0", prefix:"php5-common", reference:"5.2.6.dfsg.1-1+lenny6")) flag++;
if (deb_check(release:"5.0", prefix:"php5-curl", reference:"5.2.6.dfsg.1-1+lenny6")) flag++;
if (deb_check(release:"5.0", prefix:"php5-dbg", reference:"5.2.6.dfsg.1-1+lenny6")) flag++;
if (deb_check(release:"5.0", prefix:"php5-dev", reference:"5.2.6.dfsg.1-1+lenny6")) flag++;
if (deb_check(release:"5.0", prefix:"php5-gd", reference:"5.2.6.dfsg.1-1+lenny6")) flag++;
if (deb_check(release:"5.0", prefix:"php5-gmp", reference:"5.2.6.dfsg.1-1+lenny6")) flag++;
if (deb_check(release:"5.0", prefix:"php5-imap", reference:"5.2.6.dfsg.1-1+lenny6")) flag++;
if (deb_check(release:"5.0", prefix:"php5-interbase", reference:"5.2.6.dfsg.1-1+lenny6")) flag++;
if (deb_check(release:"5.0", prefix:"php5-ldap", reference:"5.2.6.dfsg.1-1+lenny6")) flag++;
if (deb_check(release:"5.0", prefix:"php5-mcrypt", reference:"5.2.6.dfsg.1-1+lenny6")) flag++;
if (deb_check(release:"5.0", prefix:"php5-mhash", reference:"5.2.6.dfsg.1-1+lenny6")) flag++;
if (deb_check(release:"5.0", prefix:"php5-mysql", reference:"5.2.6.dfsg.1-1+lenny6")) flag++;
if (deb_check(release:"5.0", prefix:"php5-odbc", reference:"5.2.6.dfsg.1-1+lenny6")) flag++;
if (deb_check(release:"5.0", prefix:"php5-pgsql", reference:"5.2.6.dfsg.1-1+lenny6")) flag++;
if (deb_check(release:"5.0", prefix:"php5-pspell", reference:"5.2.6.dfsg.1-1+lenny6")) flag++;
if (deb_check(release:"5.0", prefix:"php5-recode", reference:"5.2.6.dfsg.1-1+lenny6")) flag++;
if (deb_check(release:"5.0", prefix:"php5-snmp", reference:"5.2.6.dfsg.1-1+lenny6")) flag++;
if (deb_check(release:"5.0", prefix:"php5-sqlite", reference:"5.2.6.dfsg.1-1+lenny6")) flag++;
if (deb_check(release:"5.0", prefix:"php5-sybase", reference:"5.2.6.dfsg.1-1+lenny6")) flag++;
if (deb_check(release:"5.0", prefix:"php5-tidy", reference:"5.2.6.dfsg.1-1+lenny6")) flag++;
if (deb_check(release:"5.0", prefix:"php5-xmlrpc", reference:"5.2.6.dfsg.1-1+lenny6")) flag++;
if (deb_check(release:"5.0", prefix:"php5-xsl", reference:"5.2.6.dfsg.1-1+lenny6")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:deb_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
