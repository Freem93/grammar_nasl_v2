#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Debian Security Advisory DSA-1206. The text 
# itself is copyright (C) Software in the Public Interest, Inc.
#

include("compat.inc");

if (description)
{
  script_id(23655);
  script_version("$Revision: 1.13 $");
  script_cvs_date("$Date: 2014/05/03 11:14:58 $");

  script_cve_id("CVE-2005-3353", "CVE-2006-3017", "CVE-2006-4482", "CVE-2006-5465");
  script_osvdb_id(21492, 25255, 26466, 28003, 28004, 30178, 30179);
  script_xref(name:"DSA", value:"1206");

  script_name(english:"Debian DSA-1206-1 : php4 - several vulnerabilities");
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

  - CVE-2005-3353
    Tim Starling discovered that missing input sanitising in
    the EXIF module could lead to denial of service.

  - CVE-2006-3017
    Stefan Esser discovered a security-critical programming
    error in the hashtable implementation of the internal
    Zend engine.

  - CVE-2006-4482
    It was discovered that str_repeat() and wordwrap()
    functions perform insufficient checks for buffer
    boundaries on 64 bit systems, which might lead to the
    execution of arbitrary code.

  - CVE-2006-5465
    Stefan Esser discovered a buffer overflow in the
    htmlspecialchars() and htmlentities(), which might lead
    to the execution of arbitrary code."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2005-3353"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2006-3017"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2006-4482"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2006-5465"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.debian.org/security/2006/dsa-1206"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"Upgrade the php4 packages.

For the stable distribution (sarge) these problems have been fixed in
version 4:4.3.10-18. Builds for hppa and m68k will be provided later
once they are available."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_cwe_id(119);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:php4");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:3.1");

  script_set_attribute(attribute:"patch_publication_date", value:"2006/11/06");
  script_set_attribute(attribute:"plugin_publication_date", value:"2006/11/20");
  script_set_attribute(attribute:"vuln_publication_date", value:"2005/10/02");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2006-2014 Tenable Network Security, Inc.");
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
if (deb_check(release:"3.1", prefix:"libapache-mod-php4", reference:"4:4.3.10-18")) flag++;
if (deb_check(release:"3.1", prefix:"libapache2-mod-php4", reference:"4:4.3.10-18")) flag++;
if (deb_check(release:"3.1", prefix:"php4", reference:"4:4.3.10-18")) flag++;
if (deb_check(release:"3.1", prefix:"php4-cgi", reference:"4:4.3.10-18")) flag++;
if (deb_check(release:"3.1", prefix:"php4-cli", reference:"4:4.3.10-18")) flag++;
if (deb_check(release:"3.1", prefix:"php4-common", reference:"4:4.3.10-18")) flag++;
if (deb_check(release:"3.1", prefix:"php4-curl", reference:"4:4.3.10-18")) flag++;
if (deb_check(release:"3.1", prefix:"php4-dev", reference:"4:4.3.10-18")) flag++;
if (deb_check(release:"3.1", prefix:"php4-domxml", reference:"4:4.3.10-18")) flag++;
if (deb_check(release:"3.1", prefix:"php4-gd", reference:"4:4.3.10-18")) flag++;
if (deb_check(release:"3.1", prefix:"php4-imap", reference:"4:4.3.10-18")) flag++;
if (deb_check(release:"3.1", prefix:"php4-ldap", reference:"4:4.3.10-18")) flag++;
if (deb_check(release:"3.1", prefix:"php4-mcal", reference:"4:4.3.10-18")) flag++;
if (deb_check(release:"3.1", prefix:"php4-mhash", reference:"4:4.3.10-18")) flag++;
if (deb_check(release:"3.1", prefix:"php4-mysql", reference:"4:4.3.10-18")) flag++;
if (deb_check(release:"3.1", prefix:"php4-odbc", reference:"4:4.3.10-18")) flag++;
if (deb_check(release:"3.1", prefix:"php4-pear", reference:"4:4.3.10-18")) flag++;
if (deb_check(release:"3.1", prefix:"php4-recode", reference:"4:4.3.10-18")) flag++;
if (deb_check(release:"3.1", prefix:"php4-snmp", reference:"4:4.3.10-18")) flag++;
if (deb_check(release:"3.1", prefix:"php4-sybase", reference:"4:4.3.10-18")) flag++;
if (deb_check(release:"3.1", prefix:"php4-xslt", reference:"4:4.3.10-18")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:deb_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
