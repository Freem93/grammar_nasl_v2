#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Debian Security Advisory DSA-531. The text 
# itself is copyright (C) Software in the Public Interest, Inc.
#

include("compat.inc");

if (description)
{
  script_id(15368);
  script_version("$Revision: 1.20 $");
  script_cvs_date("$Date: 2013/05/18 00:11:36 $");

  script_cve_id("CVE-2004-0594", "CVE-2004-0595");
  script_xref(name:"DSA", value:"531");

  script_name(english:"Debian DSA-531-1 : php4 - several vulnerabilities");
  script_summary(english:"Checks dpkg output for the updated package");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Debian host is missing a security-related update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Two vulnerabilities were discovered in php4 :

  - CAN-2004-0594
    The memory_limit functionality in PHP 4.x up to 4.3.7,
    and 5.x up to 5.0.0RC3, under certain conditions such as
    when register_globals is enabled, allows remote
    attackers to execute arbitrary code by triggering a
    memory_limit abort during execution of the
    zend_hash_init function and overwriting a HashTable
    destructor pointer before the initialization of key data
    structures is complete.

  - CAN-2004-0595

    The strip_tags function in PHP 4.x up to 4.3.7, and 5.x
    up to 5.0.0RC3, does not filter null (\0) characters
    within tag names when restricting input to allowed tags,
    which allows dangerous tags to be processed by web
    browsers such as Internet Explorer and Safari, which
    ignore null characters and facilitate the exploitation
    of cross-site scripting (XSS) vulnerabilities."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.debian.org/security/2004/dsa-531"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"For the current stable distribution (woody), these problems have been
fixed in version 4.1.2-7.

We recommend that you update your php4 package."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_canvas", value:"true");
  script_set_attribute(attribute:"canvas_package", value:'CANVAS');

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:php4");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:3.0");

  script_set_attribute(attribute:"patch_publication_date", value:"2004/07/20");
  script_set_attribute(attribute:"plugin_publication_date", value:"2004/09/29");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2004-2013 Tenable Network Security, Inc.");
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
if (deb_check(release:"3.0", prefix:"caudium-php4", reference:"4.1.2-7")) flag++;
if (deb_check(release:"3.0", prefix:"php4", reference:"4.1.2-7")) flag++;
if (deb_check(release:"3.0", prefix:"php4-cgi", reference:"4.1.2-7")) flag++;
if (deb_check(release:"3.0", prefix:"php4-curl", reference:"4.1.2-7")) flag++;
if (deb_check(release:"3.0", prefix:"php4-dev", reference:"4.1.2-7")) flag++;
if (deb_check(release:"3.0", prefix:"php4-domxml", reference:"4.1.2-7")) flag++;
if (deb_check(release:"3.0", prefix:"php4-gd", reference:"4.1.2-7")) flag++;
if (deb_check(release:"3.0", prefix:"php4-imap", reference:"4.1.2-7")) flag++;
if (deb_check(release:"3.0", prefix:"php4-ldap", reference:"4.1.2-7")) flag++;
if (deb_check(release:"3.0", prefix:"php4-mcal", reference:"4.1.2-7")) flag++;
if (deb_check(release:"3.0", prefix:"php4-mhash", reference:"4.1.2-7")) flag++;
if (deb_check(release:"3.0", prefix:"php4-mysql", reference:"4.1.2-7")) flag++;
if (deb_check(release:"3.0", prefix:"php4-odbc", reference:"4.1.2-7")) flag++;
if (deb_check(release:"3.0", prefix:"php4-pear", reference:"4.1.2-7")) flag++;
if (deb_check(release:"3.0", prefix:"php4-recode", reference:"4.1.2-7")) flag++;
if (deb_check(release:"3.0", prefix:"php4-snmp", reference:"4.1.2-7")) flag++;
if (deb_check(release:"3.0", prefix:"php4-sybase", reference:"4.1.2-7")) flag++;
if (deb_check(release:"3.0", prefix:"php4-xslt", reference:"4.1.2-7")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:deb_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
