#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Debian Security Advisory DSA-1698. The text 
# itself is copyright (C) Software in the Public Interest, Inc.
#

include("compat.inc");

if (description)
{
  script_id(35329);
  script_version("$Revision: 1.8 $");
  script_cvs_date("$Date: 2013/05/17 23:49:55 $");

  script_cve_id("CVE-2008-2381");
  script_xref(name:"DSA", value:"1698");

  script_name(english:"Debian DSA-1698-1 : gforge - insufficient input sanitising");
  script_summary(english:"Checks dpkg output for the updated package");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Debian host is missing a security-related update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"It was discovered that GForge, a collaborative development tool,
insufficiently sanitises some input allowing a remote attacker to
perform SQL injection."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.debian.org/security/2009/dsa-1698"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"Upgrade the gforge package.

For the stable distribution (etch), this problem has been fixed in
version 4.5.14-22etch10."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_cwe_id(89);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:gforge");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:4.0");

  script_set_attribute(attribute:"patch_publication_date", value:"2009/01/09");
  script_set_attribute(attribute:"plugin_publication_date", value:"2009/01/11");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2009-2013 Tenable Network Security, Inc.");
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
if (deb_check(release:"4.0", prefix:"gforge", reference:"4.5.14-22etch10")) flag++;
if (deb_check(release:"4.0", prefix:"gforge-common", reference:"4.5.14-22etch10")) flag++;
if (deb_check(release:"4.0", prefix:"gforge-db-postgresql", reference:"4.5.14-22etch10")) flag++;
if (deb_check(release:"4.0", prefix:"gforge-dns-bind9", reference:"4.5.14-22etch10")) flag++;
if (deb_check(release:"4.0", prefix:"gforge-ftp-proftpd", reference:"4.5.14-22etch10")) flag++;
if (deb_check(release:"4.0", prefix:"gforge-ldap-openldap", reference:"4.5.14-22etch10")) flag++;
if (deb_check(release:"4.0", prefix:"gforge-lists-mailman", reference:"4.5.14-22etch10")) flag++;
if (deb_check(release:"4.0", prefix:"gforge-mta-courier", reference:"4.5.14-22etch10")) flag++;
if (deb_check(release:"4.0", prefix:"gforge-mta-exim", reference:"4.5.14-22etch10")) flag++;
if (deb_check(release:"4.0", prefix:"gforge-mta-exim4", reference:"4.5.14-22etch10")) flag++;
if (deb_check(release:"4.0", prefix:"gforge-mta-postfix", reference:"4.5.14-22etch10")) flag++;
if (deb_check(release:"4.0", prefix:"gforge-shell-ldap", reference:"4.5.14-22etch10")) flag++;
if (deb_check(release:"4.0", prefix:"gforge-shell-postgresql", reference:"4.5.14-22etch10")) flag++;
if (deb_check(release:"4.0", prefix:"gforge-web-apache", reference:"4.5.14-22etch10")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:deb_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
