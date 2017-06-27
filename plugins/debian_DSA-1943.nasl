#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Debian Security Advisory DSA-1943. The text 
# itself is copyright (C) Software in the Public Interest, Inc.
#

include("compat.inc");

if (description)
{
  script_id(44808);
  script_version("$Revision: 1.11 $");
  script_cvs_date("$Date: 2013/05/17 23:54:23 $");

  script_cve_id("CVE-2009-3767");
  script_osvdb_id(59268);
  script_xref(name:"DSA", value:"1943");

  script_name(english:"Debian DSA-1943-1 : openldap openldap2.3 - insufficient input validation");
  script_summary(english:"Checks dpkg output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Debian host is missing a security-related update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"It was discovered that OpenLDAP, a free implementation of the
Lightweight Directory Access Protocol, when OpenSSL is used, does not
properly handle a '\0' character in a domain name in the subject's
Common Name (CN) field of an X.509 certificate, which allows
man-in-the-middle attackers to spoof arbitrary SSL servers via a
crafted certificate issued by a legitimate Certification Authority."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://bugs.debian.org/cgi-bin/bugreport.cgi?bug=553432"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.debian.org/security/2009/dsa-1943"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"Upgrade the openldap2.3/openldap packages.

For the oldstable distribution (etch), this problem has been fixed in
version 2.3.30-5+etch3 for openldap2.3.

For the stable distribution (lenny), this problem has been fixed in
version 2.4.11-1+lenny1 for openldap."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_cwe_id(310);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:openldap");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:openldap2.3");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:4.0");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:5.0");

  script_set_attribute(attribute:"patch_publication_date", value:"2009/12/02");
  script_set_attribute(attribute:"plugin_publication_date", value:"2010/02/24");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2010-2013 Tenable Network Security, Inc.");
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
if (deb_check(release:"4.0", prefix:"ldap-utils", reference:"2.3.30-5+etch3")) flag++;
if (deb_check(release:"4.0", prefix:"libldap-2.3-0", reference:"2.3.30-5+etch3")) flag++;
if (deb_check(release:"4.0", prefix:"slapd", reference:"2.3.30-5+etch3")) flag++;
if (deb_check(release:"5.0", prefix:"ldap-utils", reference:"2.4.11-1+lenny1")) flag++;
if (deb_check(release:"5.0", prefix:"libldap-2.4-2", reference:"2.4.11-1+lenny1")) flag++;
if (deb_check(release:"5.0", prefix:"libldap-2.4-2-dbg", reference:"2.4.11-1+lenny1")) flag++;
if (deb_check(release:"5.0", prefix:"libldap2-dev", reference:"2.4.11-1+lenny1")) flag++;
if (deb_check(release:"5.0", prefix:"slapd", reference:"2.4.11-1+lenny1")) flag++;
if (deb_check(release:"5.0", prefix:"slapd-dbg", reference:"2.4.11-1+lenny1")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:deb_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
