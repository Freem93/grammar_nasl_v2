#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Debian Security Advisory DSA-1945. The text 
# itself is copyright (C) Software in the Public Interest, Inc.
#

include("compat.inc");

if (description)
{
  script_id(44810);
  script_version("$Revision: 1.6 $");
  script_cvs_date("$Date: 2013/05/17 23:54:23 $");

  script_cve_id("CVE-2009-3304");
  script_osvdb_id(60656);
  script_xref(name:"DSA", value:"1945");

  script_name(english:"Debian DSA-1945-1 : gforge - symlink attack");
  script_summary(english:"Checks dpkg output for the updated package");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Debian host is missing a security-related update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Sylvain Beucler discovered that gforge, a collaborative development
tool, is prone to a symlink attack, which allows local users to
perform a denial of service attack by overwriting arbitrary files.

The oldstable distribution (etch), this problem has been fixed in
version 4.5.14-22etch13."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.debian.org/security/2009/dsa-1945"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"Upgrade the gforge packages.

For the stable distribution (lenny), this problem has been fixed in
version 4.7~rc2-7lenny3."
  );
  script_set_cvss_base_vector("CVSS2#AV:L/AC:M/Au:N/C:N/I:P/A:P");
  script_cwe_id(59);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:gforge");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:4.0");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:5.0");

  script_set_attribute(attribute:"patch_publication_date", value:"2009/12/03");
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
if (deb_check(release:"4.0", prefix:"gforge", reference:"4.5.14-22etch13")) flag++;
if (deb_check(release:"4.0", prefix:"gforge-common", reference:"4.5.14-22etch13")) flag++;
if (deb_check(release:"4.0", prefix:"gforge-db-postgresql", reference:"4.5.14-22etch13")) flag++;
if (deb_check(release:"4.0", prefix:"gforge-dns-bind9", reference:"4.5.14-22etch13")) flag++;
if (deb_check(release:"4.0", prefix:"gforge-ftp-proftpd", reference:"4.5.14-22etch13")) flag++;
if (deb_check(release:"4.0", prefix:"gforge-ldap-openldap", reference:"4.5.14-22etch13")) flag++;
if (deb_check(release:"4.0", prefix:"gforge-lists-mailman", reference:"4.5.14-22etch13")) flag++;
if (deb_check(release:"4.0", prefix:"gforge-mta-courier", reference:"4.5.14-22etch13")) flag++;
if (deb_check(release:"4.0", prefix:"gforge-mta-exim", reference:"4.5.14-22etch13")) flag++;
if (deb_check(release:"4.0", prefix:"gforge-mta-exim4", reference:"4.5.14-22etch13")) flag++;
if (deb_check(release:"4.0", prefix:"gforge-mta-postfix", reference:"4.5.14-22etch13")) flag++;
if (deb_check(release:"4.0", prefix:"gforge-shell-ldap", reference:"4.5.14-22etch13")) flag++;
if (deb_check(release:"4.0", prefix:"gforge-shell-postgresql", reference:"4.5.14-22etch13")) flag++;
if (deb_check(release:"4.0", prefix:"gforge-web-apache", reference:"4.5.14-22etch13")) flag++;
if (deb_check(release:"5.0", prefix:"gforge", reference:"4.7~rc2-7lenny3")) flag++;
if (deb_check(release:"5.0", prefix:"gforge-common", reference:"4.7~rc2-7lenny3")) flag++;
if (deb_check(release:"5.0", prefix:"gforge-db-postgresql", reference:"4.7~rc2-7lenny3")) flag++;
if (deb_check(release:"5.0", prefix:"gforge-dns-bind9", reference:"4.7~rc2-7lenny3")) flag++;
if (deb_check(release:"5.0", prefix:"gforge-ftp-proftpd", reference:"4.7~rc2-7lenny3")) flag++;
if (deb_check(release:"5.0", prefix:"gforge-lists-mailman", reference:"4.7~rc2-7lenny3")) flag++;
if (deb_check(release:"5.0", prefix:"gforge-mta-courier", reference:"4.7~rc2-7lenny3")) flag++;
if (deb_check(release:"5.0", prefix:"gforge-mta-exim4", reference:"4.7~rc2-7lenny3")) flag++;
if (deb_check(release:"5.0", prefix:"gforge-mta-postfix", reference:"4.7~rc2-7lenny3")) flag++;
if (deb_check(release:"5.0", prefix:"gforge-plugin-mediawiki", reference:"4.7~rc2-7lenny3")) flag++;
if (deb_check(release:"5.0", prefix:"gforge-plugin-scmcvs", reference:"4.7~rc2-7lenny3")) flag++;
if (deb_check(release:"5.0", prefix:"gforge-plugin-scmsvn", reference:"4.7~rc2-7lenny3")) flag++;
if (deb_check(release:"5.0", prefix:"gforge-shell-postgresql", reference:"4.7~rc2-7lenny3")) flag++;
if (deb_check(release:"5.0", prefix:"gforge-web-apache", reference:"4.7~rc2-7lenny3")) flag++;
if (deb_check(release:"5.0", prefix:"gforge-web-apache2", reference:"4.7~rc2-7lenny3")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_note(port:0, extra:deb_report_get());
  else security_note(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
