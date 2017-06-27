#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Debian Security Advisory DSA-1094. The text 
# itself is copyright (C) Software in the Public Interest, Inc.
#

include("compat.inc");

if (description)
{
  script_id(22636);
  script_version("$Revision: 1.13 $");
  script_cvs_date("$Date: 2013/05/17 23:36:52 $");

  script_cve_id("CVE-2005-2430");
  script_osvdb_id(18302);
  script_xref(name:"DSA", value:"1094");

  script_name(english:"Debian DSA-1094-1 : gforge - missing input sanitising");
  script_summary(english:"Checks dpkg output for the updated package");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Debian host is missing a security-related update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Joxean Koret discovered several cross-site scripting vulnerabilities
in Gforge, an online collaboration suite for software development,
which allow injection of web script code."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://bugs.debian.org/cgi-bin/bugreport.cgi?bug=328224"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.debian.org/security/2006/dsa-1094"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"Upgrade the gforge package.

The old stable distribution (woody) does not contain gforge packages.

For the stable distribution (sarge) this problem has been fixed in
version 3.1-31sarge1."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:P/A:N");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:gforge");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:3.1");

  script_set_attribute(attribute:"patch_publication_date", value:"2006/06/08");
  script_set_attribute(attribute:"plugin_publication_date", value:"2006/10/14");
  script_set_attribute(attribute:"vuln_publication_date", value:"2005/07/28");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2006-2013 Tenable Network Security, Inc.");
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
if (deb_check(release:"3.1", prefix:"gforge", reference:"3.1-31sarge1")) flag++;
if (deb_check(release:"3.1", prefix:"gforge-common", reference:"3.1-31sarge1")) flag++;
if (deb_check(release:"3.1", prefix:"gforge-cvs", reference:"3.1-31sarge1")) flag++;
if (deb_check(release:"3.1", prefix:"gforge-db-postgresql", reference:"3.1-31sarge1")) flag++;
if (deb_check(release:"3.1", prefix:"gforge-dns-bind9", reference:"3.1-31sarge1")) flag++;
if (deb_check(release:"3.1", prefix:"gforge-ftp-proftpd", reference:"3.1-31sarge1")) flag++;
if (deb_check(release:"3.1", prefix:"gforge-ldap-openldap", reference:"3.1-31sarge1")) flag++;
if (deb_check(release:"3.1", prefix:"gforge-lists-mailman", reference:"3.1-31sarge1")) flag++;
if (deb_check(release:"3.1", prefix:"gforge-mta-exim", reference:"3.1-31sarge1")) flag++;
if (deb_check(release:"3.1", prefix:"gforge-mta-exim4", reference:"3.1-31sarge1")) flag++;
if (deb_check(release:"3.1", prefix:"gforge-mta-postfix", reference:"3.1-31sarge1")) flag++;
if (deb_check(release:"3.1", prefix:"gforge-shell-ldap", reference:"3.1-31sarge1")) flag++;
if (deb_check(release:"3.1", prefix:"gforge-sourceforge-transition", reference:"3.1-31sarge1")) flag++;
if (deb_check(release:"3.1", prefix:"gforge-web-apache", reference:"3.1-31sarge1")) flag++;
if (deb_check(release:"3.1", prefix:"sourceforge", reference:"3.1-31sarge1")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:deb_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
