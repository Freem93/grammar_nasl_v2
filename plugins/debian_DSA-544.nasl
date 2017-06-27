#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Debian Security Advisory DSA-544. The text 
# itself is copyright (C) Software in the Public Interest, Inc.
#

include("compat.inc");

if (description)
{
  script_id(15381);
  script_version("$Revision: 1.18 $");
  script_cvs_date("$Date: 2013/05/18 00:11:36 $");

  script_cve_id("CVE-2004-0559", "CVE-2004-1468");
  script_osvdb_id(9775, 9776);
  script_xref(name:"DSA", value:"544");

  script_name(english:"Debian DSA-544-1 : webmin - insecure temporary directory");
  script_summary(english:"Checks dpkg output for the updated package");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Debian host is missing a security-related update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Ludwig Nussel discovered a problem in webmin, a web-based
administration toolkit. A temporary directory was used but without
checking for the previous owner. This could allow an attacker to
create the directory and place dangerous symbolic links inside."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.debian.org/security/2004/dsa-544"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"Upgrade the webmin packages.

For the stable distribution (woody) this problem has been fixed in
version 0.94-7woody3."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:webmin");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:3.0");

  script_set_attribute(attribute:"patch_publication_date", value:"2004/09/14");
  script_set_attribute(attribute:"plugin_publication_date", value:"2004/09/29");
  script_set_attribute(attribute:"vuln_publication_date", value:"2004/09/05");
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
if (deb_check(release:"3.0", prefix:"webmin", reference:"0.94-7woody3")) flag++;
if (deb_check(release:"3.0", prefix:"webmin-apache", reference:"0.94-7woody3")) flag++;
if (deb_check(release:"3.0", prefix:"webmin-bind8", reference:"0.94-7woody3")) flag++;
if (deb_check(release:"3.0", prefix:"webmin-burner", reference:"0.94-7woody3")) flag++;
if (deb_check(release:"3.0", prefix:"webmin-cluster-software", reference:"0.94-7woody3")) flag++;
if (deb_check(release:"3.0", prefix:"webmin-cluster-useradmin", reference:"0.94-7woody3")) flag++;
if (deb_check(release:"3.0", prefix:"webmin-core", reference:"0.94-7woody3")) flag++;
if (deb_check(release:"3.0", prefix:"webmin-cpan", reference:"0.94-7woody3")) flag++;
if (deb_check(release:"3.0", prefix:"webmin-dhcpd", reference:"0.94-7woody3")) flag++;
if (deb_check(release:"3.0", prefix:"webmin-exports", reference:"0.94-7woody3")) flag++;
if (deb_check(release:"3.0", prefix:"webmin-fetchmail", reference:"0.94-7woody3")) flag++;
if (deb_check(release:"3.0", prefix:"webmin-grub", reference:"0.94-7woody3")) flag++;
if (deb_check(release:"3.0", prefix:"webmin-heartbeat", reference:"0.94-7woody3")) flag++;
if (deb_check(release:"3.0", prefix:"webmin-inetd", reference:"0.94-7woody3")) flag++;
if (deb_check(release:"3.0", prefix:"webmin-jabber", reference:"0.94-7woody3")) flag++;
if (deb_check(release:"3.0", prefix:"webmin-lpadmin", reference:"0.94-7woody3")) flag++;
if (deb_check(release:"3.0", prefix:"webmin-mon", reference:"0.94-7woody3")) flag++;
if (deb_check(release:"3.0", prefix:"webmin-mysql", reference:"0.94-7woody3")) flag++;
if (deb_check(release:"3.0", prefix:"webmin-nis", reference:"0.94-7woody3")) flag++;
if (deb_check(release:"3.0", prefix:"webmin-postfix", reference:"0.94-7woody3")) flag++;
if (deb_check(release:"3.0", prefix:"webmin-postgresql", reference:"0.94-7woody3")) flag++;
if (deb_check(release:"3.0", prefix:"webmin-ppp", reference:"0.94-7woody3")) flag++;
if (deb_check(release:"3.0", prefix:"webmin-qmailadmin", reference:"0.94-7woody3")) flag++;
if (deb_check(release:"3.0", prefix:"webmin-quota", reference:"0.94-7woody3")) flag++;
if (deb_check(release:"3.0", prefix:"webmin-raid", reference:"0.94-7woody3")) flag++;
if (deb_check(release:"3.0", prefix:"webmin-samba", reference:"0.94-7woody3")) flag++;
if (deb_check(release:"3.0", prefix:"webmin-sendmail", reference:"0.94-7woody3")) flag++;
if (deb_check(release:"3.0", prefix:"webmin-software", reference:"0.94-7woody3")) flag++;
if (deb_check(release:"3.0", prefix:"webmin-squid", reference:"0.94-7woody3")) flag++;
if (deb_check(release:"3.0", prefix:"webmin-sshd", reference:"0.94-7woody3")) flag++;
if (deb_check(release:"3.0", prefix:"webmin-ssl", reference:"0.94-7woody3")) flag++;
if (deb_check(release:"3.0", prefix:"webmin-status", reference:"0.94-7woody3")) flag++;
if (deb_check(release:"3.0", prefix:"webmin-stunnel", reference:"0.94-7woody3")) flag++;
if (deb_check(release:"3.0", prefix:"webmin-wuftpd", reference:"0.94-7woody3")) flag++;
if (deb_check(release:"3.0", prefix:"webmin-xinetd", reference:"0.94-7woody3")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:deb_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
