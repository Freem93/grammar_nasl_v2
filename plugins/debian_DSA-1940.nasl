#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Debian Security Advisory DSA-1940. The text 
# itself is copyright (C) Software in the Public Interest, Inc.
#

include("compat.inc");

if (description)
{
  script_id(44805);
  script_version("$Revision: 1.10 $");
  script_cvs_date("$Date: 2016/12/06 20:25:07 $");

  script_cve_id("CVE-2008-5658", "CVE-2009-2626", "CVE-2009-2687", "CVE-2009-3291", "CVE-2009-3292");
  script_bugtraq_id(35440, 36449, 37079);
  script_osvdb_id(58185, 60654);
  script_xref(name:"DSA", value:"1940");

  script_name(english:"Debian DSA-1940-1 : php5 - multiple issues");
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
project identifies the following problems :

The following issues have been fixed in both the stable (lenny) and
the oldstable (etch) distributions :

  - CVE-2009-2687 CVE-2009-3292
    The exif module did not properly handle malformed jpeg
    files, allowing an attacker to cause a segfault,
    resulting in a denial of service.

  - CVE-2009-3291
    The php_openssl_apply_verification_policy() function did
    not properly perform certificate validation.

  - No CVE id yet

    Bogdan Calin discovered that a remote attacker could
    cause a denial of service by uploading a large number of
    files in using multipart/ form-data requests, causing
    the creation of a large number of temporary files.

  To address this issue, the max_file_uploads option introduced in PHP
  5.3.1 has been backported. This option limits the maximum number of
  files uploaded per request. The default value for this new option is
  50. See NEWS.Debian for more information.

The following issue has been fixed in the stable (lenny) distribution
:

  - CVE-2009-2626
    A flaw in the ini_restore() function could lead to a
    memory disclosure, possibly leading to the disclosure of
    sensitive data.

In the oldstable (etch) distribution, this update also fixes a
regression introduced by the fix for CVE-2008-5658 in DSA-1789-1 (bug
#527560)."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://bugs.debian.org/cgi-bin/bugreport.cgi?bug=535888"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://bugs.debian.org/cgi-bin/bugreport.cgi?bug=540605"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://bugs.debian.org/cgi-bin/bugreport.cgi?bug=527560"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2009-2687"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2009-3292"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2009-3291"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2009-2626"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2008-5658"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.debian.org/security/2009/dsa-1940"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"Upgrade the php5 packages.

For the stable distribution (lenny), these problems have been fixed in
version 5.2.6.dfsg.1-1+lenny4.

The oldstable distribution (etch), these problems have been fixed in
version 5.2.0+dfsg-8+etch16."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_cwe_id(20, 22);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:php5");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:4.0");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:5.0");

  script_set_attribute(attribute:"patch_publication_date", value:"2009/11/25");
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
if (deb_check(release:"4.0", prefix:"libapache-mod-php5", reference:"5.2.0+dfsg-8+etch16")) flag++;
if (deb_check(release:"4.0", prefix:"libapache2-mod-php5", reference:"5.2.0+dfsg-8+etch16")) flag++;
if (deb_check(release:"4.0", prefix:"php-pear", reference:"5.2.0+dfsg-8+etch16")) flag++;
if (deb_check(release:"4.0", prefix:"php5", reference:"5.2.0+dfsg-8+etch16")) flag++;
if (deb_check(release:"4.0", prefix:"php5-cgi", reference:"5.2.0+dfsg-8+etch16")) flag++;
if (deb_check(release:"4.0", prefix:"php5-cli", reference:"5.2.0+dfsg-8+etch16")) flag++;
if (deb_check(release:"4.0", prefix:"php5-common", reference:"5.2.0+dfsg-8+etch16")) flag++;
if (deb_check(release:"4.0", prefix:"php5-curl", reference:"5.2.0+dfsg-8+etch16")) flag++;
if (deb_check(release:"4.0", prefix:"php5-dev", reference:"5.2.0+dfsg-8+etch16")) flag++;
if (deb_check(release:"4.0", prefix:"php5-gd", reference:"5.2.0+dfsg-8+etch16")) flag++;
if (deb_check(release:"4.0", prefix:"php5-imap", reference:"5.2.0+dfsg-8+etch16")) flag++;
if (deb_check(release:"4.0", prefix:"php5-interbase", reference:"5.2.0+dfsg-8+etch16")) flag++;
if (deb_check(release:"4.0", prefix:"php5-ldap", reference:"5.2.0+dfsg-8+etch16")) flag++;
if (deb_check(release:"4.0", prefix:"php5-mcrypt", reference:"5.2.0+dfsg-8+etch16")) flag++;
if (deb_check(release:"4.0", prefix:"php5-mhash", reference:"5.2.0+dfsg-8+etch16")) flag++;
if (deb_check(release:"4.0", prefix:"php5-mysql", reference:"5.2.0+dfsg-8+etch16")) flag++;
if (deb_check(release:"4.0", prefix:"php5-odbc", reference:"5.2.0+dfsg-8+etch16")) flag++;
if (deb_check(release:"4.0", prefix:"php5-pgsql", reference:"5.2.0+dfsg-8+etch16")) flag++;
if (deb_check(release:"4.0", prefix:"php5-pspell", reference:"5.2.0+dfsg-8+etch16")) flag++;
if (deb_check(release:"4.0", prefix:"php5-recode", reference:"5.2.0+dfsg-8+etch16")) flag++;
if (deb_check(release:"4.0", prefix:"php5-snmp", reference:"5.2.0+dfsg-8+etch16")) flag++;
if (deb_check(release:"4.0", prefix:"php5-sqlite", reference:"5.2.0+dfsg-8+etch16")) flag++;
if (deb_check(release:"4.0", prefix:"php5-sybase", reference:"5.2.0+dfsg-8+etch16")) flag++;
if (deb_check(release:"4.0", prefix:"php5-tidy", reference:"5.2.0+dfsg-8+etch16")) flag++;
if (deb_check(release:"4.0", prefix:"php5-xmlrpc", reference:"5.2.0+dfsg-8+etch16")) flag++;
if (deb_check(release:"4.0", prefix:"php5-xsl", reference:"5.2.0+dfsg-8+etch16")) flag++;
if (deb_check(release:"5.0", prefix:"libapache2-mod-php5", reference:"5.2.6.dfsg.1-1+lenny4")) flag++;
if (deb_check(release:"5.0", prefix:"libapache2-mod-php5filter", reference:"5.2.6.dfsg.1-1+lenny4")) flag++;
if (deb_check(release:"5.0", prefix:"php-pear", reference:"5.2.6.dfsg.1-1+lenny4")) flag++;
if (deb_check(release:"5.0", prefix:"php5", reference:"5.2.6.dfsg.1-1+lenny4")) flag++;
if (deb_check(release:"5.0", prefix:"php5-cgi", reference:"5.2.6.dfsg.1-1+lenny4")) flag++;
if (deb_check(release:"5.0", prefix:"php5-cli", reference:"5.2.6.dfsg.1-1+lenny4")) flag++;
if (deb_check(release:"5.0", prefix:"php5-common", reference:"5.2.6.dfsg.1-1+lenny4")) flag++;
if (deb_check(release:"5.0", prefix:"php5-curl", reference:"5.2.6.dfsg.1-1+lenny4")) flag++;
if (deb_check(release:"5.0", prefix:"php5-dbg", reference:"5.2.6.dfsg.1-1+lenny4")) flag++;
if (deb_check(release:"5.0", prefix:"php5-dev", reference:"5.2.6.dfsg.1-1+lenny4")) flag++;
if (deb_check(release:"5.0", prefix:"php5-gd", reference:"5.2.6.dfsg.1-1+lenny4")) flag++;
if (deb_check(release:"5.0", prefix:"php5-gmp", reference:"5.2.6.dfsg.1-1+lenny4")) flag++;
if (deb_check(release:"5.0", prefix:"php5-imap", reference:"5.2.6.dfsg.1-1+lenny4")) flag++;
if (deb_check(release:"5.0", prefix:"php5-interbase", reference:"5.2.6.dfsg.1-1+lenny4")) flag++;
if (deb_check(release:"5.0", prefix:"php5-ldap", reference:"5.2.6.dfsg.1-1+lenny4")) flag++;
if (deb_check(release:"5.0", prefix:"php5-mcrypt", reference:"5.2.6.dfsg.1-1+lenny4")) flag++;
if (deb_check(release:"5.0", prefix:"php5-mhash", reference:"5.2.6.dfsg.1-1+lenny4")) flag++;
if (deb_check(release:"5.0", prefix:"php5-mysql", reference:"5.2.6.dfsg.1-1+lenny4")) flag++;
if (deb_check(release:"5.0", prefix:"php5-odbc", reference:"5.2.6.dfsg.1-1+lenny4")) flag++;
if (deb_check(release:"5.0", prefix:"php5-pgsql", reference:"5.2.6.dfsg.1-1+lenny4")) flag++;
if (deb_check(release:"5.0", prefix:"php5-pspell", reference:"5.2.6.dfsg.1-1+lenny4")) flag++;
if (deb_check(release:"5.0", prefix:"php5-recode", reference:"5.2.6.dfsg.1-1+lenny4")) flag++;
if (deb_check(release:"5.0", prefix:"php5-snmp", reference:"5.2.6.dfsg.1-1+lenny4")) flag++;
if (deb_check(release:"5.0", prefix:"php5-sqlite", reference:"5.2.6.dfsg.1-1+lenny4")) flag++;
if (deb_check(release:"5.0", prefix:"php5-sybase", reference:"5.2.6.dfsg.1-1+lenny4")) flag++;
if (deb_check(release:"5.0", prefix:"php5-tidy", reference:"5.2.6.dfsg.1-1+lenny4")) flag++;
if (deb_check(release:"5.0", prefix:"php5-xmlrpc", reference:"5.2.6.dfsg.1-1+lenny4")) flag++;
if (deb_check(release:"5.0", prefix:"php5-xsl", reference:"5.2.6.dfsg.1-1+lenny4")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:deb_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
