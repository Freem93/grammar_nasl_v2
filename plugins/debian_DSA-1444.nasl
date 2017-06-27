#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Debian Security Advisory DSA-1444. The text 
# itself is copyright (C) Software in the Public Interest, Inc.
#

if (NASL_LEVEL < 3000) exit(0);

include("compat.inc");

if (description)
{
  script_id(29838);
  script_version("$Revision: 1.20 $");
  script_cvs_date("$Date: 2016/12/06 20:12:50 $");

  script_cve_id("CVE-2007-3799", "CVE-2007-3998", "CVE-2007-4657", "CVE-2007-4658", "CVE-2007-4659", "CVE-2007-4660", "CVE-2007-4662", "CVE-2007-5898", "CVE-2007-5899");
  script_bugtraq_id(24268, 25498, 26403);
  script_osvdb_id(36855, 36858, 36859, 36861, 36862, 36864, 36865, 38683, 38918, 45874);
  script_xref(name:"DSA", value:"1444");

  script_name(english:"Debian DSA-1444-2 : php5 - several vulnerabilities");
  script_summary(english:"Checks dpkg output for the updated package");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Debian host is missing a security-related update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"It was discovered that the patch for CVE-2007-4659 could lead to
regressions in some scenarios. The fix has been reverted for now, a
revised update will be provided in a future PHP DSA.

For reference the original advisory below :

Several remote vulnerabilities have been discovered in PHP, a
server-side, HTML-embedded scripting language. The Common
Vulnerabilities and Exposures project identifies the following
problems :

  - CVE-2007-3799
    It was discovered that the session_start() function
    allowed the insertion of attributes into the session
    cookie.

  - CVE-2007-3998
    Mattias Bengtsson and Philip Olausson discovered that a
    programming error in the implementation of the
    wordwrap() function allowed denial of service through an
    infinite loop.

  - CVE-2007-4658
    Stanislav Malyshev discovered that a format string
    vulnerability in the money_format() function could allow
    the execution of arbitrary code.

  - CVE-2007-4659
    Stefan Esser discovered that execution control flow
    inside the zend_alter_ini_entry() function is handled
    incorrectly in case of a memory limit violation.

  - CVE-2007-4660
    Gerhard Wagner discovered an integer overflow inside the
    chunk_split() function.

  - CVE-2007-5898
    Rasmus Lerdorf discovered that incorrect parsing of
    multibyte sequences may lead to disclosure of memory
    contents.

  - CVE-2007-5899
    It was discovered that the output_add_rewrite_var()
    function could leak session ID information, resulting in
    information disclosure.

This update also fixes two bugs from the PHP 5.2.4 release which don't
have security impact according to the Debian PHP security policy
(CVE-2007-4657 and CVE-2007-4662 ), but which are fixed nonetheless."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2007-4659"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2007-3799"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2007-3998"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2007-4658"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2007-4659"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2007-4660"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2007-5898"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2007-5899"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2007-4657"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2007-4662"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2007-5898"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2007-5899"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.debian.org/security/2008/dsa-1444"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"Upgrade the php5 packages.

The old stable distribution (sarge) doesn't contain php5.

For the stable distribution (etch), these problems have been fixed in
version 5.2.0-8+etch10."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:ND/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_cwe_id(20, 119, 189, 200, 399);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:php5");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:4.0");

  script_set_attribute(attribute:"patch_publication_date", value:"2008/01/23");
  script_set_attribute(attribute:"plugin_publication_date", value:"2008/01/04");
  script_set_attribute(attribute:"vuln_publication_date", value:"2007/06/01");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2008-2016 Tenable Network Security, Inc.");
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
if (deb_check(release:"4.0", prefix:"libapache-mod-php5", reference:"5.2.0-8+etch10")) flag++;
if (deb_check(release:"4.0", prefix:"libapache2-mod-php5", reference:"5.2.0-8+etch10")) flag++;
if (deb_check(release:"4.0", prefix:"php-pear", reference:"5.2.0-8+etch10")) flag++;
if (deb_check(release:"4.0", prefix:"php5", reference:"5.2.0-8+etch10")) flag++;
if (deb_check(release:"4.0", prefix:"php5-cgi", reference:"5.2.0-8+etch10")) flag++;
if (deb_check(release:"4.0", prefix:"php5-cli", reference:"5.2.0-8+etch10")) flag++;
if (deb_check(release:"4.0", prefix:"php5-common", reference:"5.2.0-8+etch10")) flag++;
if (deb_check(release:"4.0", prefix:"php5-curl", reference:"5.2.0-8+etch10")) flag++;
if (deb_check(release:"4.0", prefix:"php5-dev", reference:"5.2.0-8+etch10")) flag++;
if (deb_check(release:"4.0", prefix:"php5-gd", reference:"5.2.0-8+etch10")) flag++;
if (deb_check(release:"4.0", prefix:"php5-imap", reference:"5.2.0-8+etch10")) flag++;
if (deb_check(release:"4.0", prefix:"php5-interbase", reference:"5.2.0-8+etch10")) flag++;
if (deb_check(release:"4.0", prefix:"php5-ldap", reference:"5.2.0-8+etch10")) flag++;
if (deb_check(release:"4.0", prefix:"php5-mcrypt", reference:"5.2.0-8+etch10")) flag++;
if (deb_check(release:"4.0", prefix:"php5-mhash", reference:"5.2.0-8+etch10")) flag++;
if (deb_check(release:"4.0", prefix:"php5-mysql", reference:"5.2.0-8+etch10")) flag++;
if (deb_check(release:"4.0", prefix:"php5-odbc", reference:"5.2.0-8+etch10")) flag++;
if (deb_check(release:"4.0", prefix:"php5-pgsql", reference:"5.2.0-8+etch10")) flag++;
if (deb_check(release:"4.0", prefix:"php5-pspell", reference:"5.2.0-8+etch10")) flag++;
if (deb_check(release:"4.0", prefix:"php5-recode", reference:"5.2.0-8+etch10")) flag++;
if (deb_check(release:"4.0", prefix:"php5-snmp", reference:"5.2.0-8+etch10")) flag++;
if (deb_check(release:"4.0", prefix:"php5-sqlite", reference:"5.2.0-8+etch10")) flag++;
if (deb_check(release:"4.0", prefix:"php5-sybase", reference:"5.2.0-8+etch10")) flag++;
if (deb_check(release:"4.0", prefix:"php5-tidy", reference:"5.2.0-8+etch10")) flag++;
if (deb_check(release:"4.0", prefix:"php5-xmlrpc", reference:"5.2.0-8+etch10")) flag++;
if (deb_check(release:"4.0", prefix:"php5-xsl", reference:"5.2.0-8+etch10")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:deb_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
