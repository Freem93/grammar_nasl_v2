#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Debian Security Advisory DSA-1331. The text 
# itself is copyright (C) Software in the Public Interest, Inc.
#

include("compat.inc");

if (description)
{
  script_id(25678);
  script_version("$Revision: 1.13 $");
  script_cvs_date("$Date: 2014/05/03 11:14:58 $");

  script_cve_id("CVE-2006-0207", "CVE-2006-4486", "CVE-2007-1864");
  script_osvdb_id(22478, 28001, 34674);
  script_xref(name:"DSA", value:"1331");

  script_name(english:"Debian DSA-1331-1 : php4 - several vulnerabilities");
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

  - CVE-2006-0207
    Stefan Esser discovered HTTP response splitting
    vulnerabilities in the session extension. This only
    affects Debian 3.1 (Sarge).

  - CVE-2006-4486
    Stefan Esser discovered that an integer overflow in
    memory allocation routines allows the bypass of memory
    limit restrictions. This only affects Debian 3.1 (Sarge)
    on 64 bit architectures.

  - CVE-2007-1864
    It was discovered that a buffer overflow in the xmlrpc
    extension allows the execution of arbitrary code."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2006-0207"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2006-4486"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2007-1864"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.debian.org/security/2007/dsa-1331"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"Upgrade the PHP packages. Sarge packages for hppa, mips and powerpc
are not yet available, due to problems on the build hosts. They will
be provided later.

For the oldstable distribution (sarge) these problems have been fixed
in version 4.3.10-22.

For the stable distribution (etch) these problems have been fixed in
version 4.4.4-8+etch4."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_cwe_id(119);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:php4");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:3.1");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:4.0");

  script_set_attribute(attribute:"patch_publication_date", value:"2007/07/07");
  script_set_attribute(attribute:"plugin_publication_date", value:"2007/07/10");
  script_set_attribute(attribute:"vuln_publication_date", value:"2006/01/12");
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
if (deb_check(release:"3.1", prefix:"libapache-mod-php4", reference:"4.3.10-22")) flag++;
if (deb_check(release:"3.1", prefix:"libapache2-mod-php4", reference:"4.3.10-22")) flag++;
if (deb_check(release:"3.1", prefix:"php4", reference:"4.3.10-22")) flag++;
if (deb_check(release:"3.1", prefix:"php4-cgi", reference:"4.3.10-22")) flag++;
if (deb_check(release:"3.1", prefix:"php4-cli", reference:"4.3.10-22")) flag++;
if (deb_check(release:"3.1", prefix:"php4-common", reference:"4.3.10-22")) flag++;
if (deb_check(release:"3.1", prefix:"php4-curl", reference:"4.3.10-22")) flag++;
if (deb_check(release:"3.1", prefix:"php4-dev", reference:"4.3.10-22")) flag++;
if (deb_check(release:"3.1", prefix:"php4-domxml", reference:"4.3.10-22")) flag++;
if (deb_check(release:"3.1", prefix:"php4-gd", reference:"4.3.10-22")) flag++;
if (deb_check(release:"3.1", prefix:"php4-imap", reference:"4.3.10-22")) flag++;
if (deb_check(release:"3.1", prefix:"php4-ldap", reference:"4.3.10-22")) flag++;
if (deb_check(release:"3.1", prefix:"php4-mcal", reference:"4.3.10-22")) flag++;
if (deb_check(release:"3.1", prefix:"php4-mhash", reference:"4.3.10-22")) flag++;
if (deb_check(release:"3.1", prefix:"php4-mysql", reference:"4.3.10-22")) flag++;
if (deb_check(release:"3.1", prefix:"php4-odbc", reference:"4.3.10-22")) flag++;
if (deb_check(release:"3.1", prefix:"php4-pear", reference:"4.3.10-22")) flag++;
if (deb_check(release:"3.1", prefix:"php4-recode", reference:"4.3.10-22")) flag++;
if (deb_check(release:"3.1", prefix:"php4-snmp", reference:"4.3.10-22")) flag++;
if (deb_check(release:"3.1", prefix:"php4-sybase", reference:"4.3.10-22")) flag++;
if (deb_check(release:"3.1", prefix:"php4-xslt", reference:"4.3.10-22")) flag++;
if (deb_check(release:"4.0", prefix:"libapache-mod-php4", reference:"4.4.4-8+etch4")) flag++;
if (deb_check(release:"4.0", prefix:"libapache2-mod-php4", reference:"4.4.4-8+etch4")) flag++;
if (deb_check(release:"4.0", prefix:"php4", reference:"4.4.4-8+etch4")) flag++;
if (deb_check(release:"4.0", prefix:"php4-cgi", reference:"4.4.4-8+etch4")) flag++;
if (deb_check(release:"4.0", prefix:"php4-cli", reference:"4.4.4-8+etch4")) flag++;
if (deb_check(release:"4.0", prefix:"php4-common", reference:"4.4.4-8+etch4")) flag++;
if (deb_check(release:"4.0", prefix:"php4-curl", reference:"4.4.4-8+etch4")) flag++;
if (deb_check(release:"4.0", prefix:"php4-dev", reference:"4.4.4-8+etch4")) flag++;
if (deb_check(release:"4.0", prefix:"php4-domxml", reference:"4.4.4-8+etch4")) flag++;
if (deb_check(release:"4.0", prefix:"php4-gd", reference:"4.4.4-8+etch4")) flag++;
if (deb_check(release:"4.0", prefix:"php4-imap", reference:"4.4.4-8+etch4")) flag++;
if (deb_check(release:"4.0", prefix:"php4-interbase", reference:"4.4.4-8+etch4")) flag++;
if (deb_check(release:"4.0", prefix:"php4-ldap", reference:"4.4.4-8+etch4")) flag++;
if (deb_check(release:"4.0", prefix:"php4-mcal", reference:"4.4.4-8+etch4")) flag++;
if (deb_check(release:"4.0", prefix:"php4-mcrypt", reference:"4.4.4-8+etch4")) flag++;
if (deb_check(release:"4.0", prefix:"php4-mhash", reference:"4.4.4-8+etch4")) flag++;
if (deb_check(release:"4.0", prefix:"php4-mysql", reference:"4.4.4-8+etch4")) flag++;
if (deb_check(release:"4.0", prefix:"php4-odbc", reference:"4.4.4-8+etch4")) flag++;
if (deb_check(release:"4.0", prefix:"php4-pear", reference:"4.4.4-8+etch4")) flag++;
if (deb_check(release:"4.0", prefix:"php4-pgsql", reference:"4.4.4-8+etch4")) flag++;
if (deb_check(release:"4.0", prefix:"php4-pspell", reference:"4.4.4-8+etch4")) flag++;
if (deb_check(release:"4.0", prefix:"php4-recode", reference:"4.4.4-8+etch4")) flag++;
if (deb_check(release:"4.0", prefix:"php4-snmp", reference:"4.4.4-8+etch4")) flag++;
if (deb_check(release:"4.0", prefix:"php4-sybase", reference:"4.4.4-8+etch4")) flag++;
if (deb_check(release:"4.0", prefix:"php4-xslt", reference:"4.4.4-8+etch4")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:deb_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
