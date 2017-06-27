#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Debian Security Advisory DSA-526. The text 
# itself is copyright (C) Software in the Public Interest, Inc.
#

include("compat.inc");

if (description)
{
  script_id(15363);
  script_version("$Revision: 1.22 $");
  script_cvs_date("$Date: 2013/12/05 14:06:23 $");

  script_cve_id("CVE-2004-0582", "CVE-2004-0583");
  script_bugtraq_id(10474);
  script_osvdb_id(6729, 6730);
  script_xref(name:"DSA", value:"526");

  script_name(english:"Debian DSA-526-1 : webmin - several vulnerabilities");
  script_summary(english:"Checks dpkg output for the updated package");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Debian host is missing a security-related update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Two vulnerabilities were discovered in webmin :

 CAN-2004-0582: Unknown vulnerability in Webmin 1.140 allows remote
 attackers to bypass access control rules and gain read access to
 configuration information for a module.

 CAN-2004-0583: The account lockout functionality in (1) Webmin 1.140
 and (2) Usermin 1.070 does not parse certain character strings, which
 allows remote attackers to conduct a brute-force attack to guess user
 IDs and passwords."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.debian.org/security/2004/dsa-526"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"For the current stable distribution (woody), these problems have been
fixed in version 0.94-7woody2.

We recommend that you update your webmin package."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:H/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No exploit is required");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:webmin");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:3.0");

  script_set_attribute(attribute:"patch_publication_date", value:"2004/07/03");
  script_set_attribute(attribute:"plugin_publication_date", value:"2004/09/29");
  script_set_attribute(attribute:"vuln_publication_date", value:"2004/06/03");
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
if (deb_check(release:"3.0", prefix:"webmin", reference:"0.94-7woody2")) flag++;
if (deb_check(release:"3.0", prefix:"webmin-apache", reference:"0.94-7woody2")) flag++;
if (deb_check(release:"3.0", prefix:"webmin-bind8", reference:"0.94-7woody2")) flag++;
if (deb_check(release:"3.0", prefix:"webmin-burner", reference:"0.94-7woody2")) flag++;
if (deb_check(release:"3.0", prefix:"webmin-cluster-software", reference:"0.94-7woody2")) flag++;
if (deb_check(release:"3.0", prefix:"webmin-cluster-useradmin", reference:"0.94-7woody2")) flag++;
if (deb_check(release:"3.0", prefix:"webmin-core", reference:"0.94-7woody2")) flag++;
if (deb_check(release:"3.0", prefix:"webmin-cpan", reference:"0.94-7woody2")) flag++;
if (deb_check(release:"3.0", prefix:"webmin-dhcpd", reference:"0.94-7woody2")) flag++;
if (deb_check(release:"3.0", prefix:"webmin-exports", reference:"0.94-7woody2")) flag++;
if (deb_check(release:"3.0", prefix:"webmin-fetchmail", reference:"0.94-7woody2")) flag++;
if (deb_check(release:"3.0", prefix:"webmin-grub", reference:"0.94-7woody2")) flag++;
if (deb_check(release:"3.0", prefix:"webmin-heartbeat", reference:"0.94-7woody2")) flag++;
if (deb_check(release:"3.0", prefix:"webmin-inetd", reference:"0.94-7woody2")) flag++;
if (deb_check(release:"3.0", prefix:"webmin-jabber", reference:"0.94-7woody2")) flag++;
if (deb_check(release:"3.0", prefix:"webmin-lpadmin", reference:"0.94-7woody2")) flag++;
if (deb_check(release:"3.0", prefix:"webmin-mon", reference:"0.94-7woody2")) flag++;
if (deb_check(release:"3.0", prefix:"webmin-mysql", reference:"0.94-7woody2")) flag++;
if (deb_check(release:"3.0", prefix:"webmin-nis", reference:"0.94-7woody2")) flag++;
if (deb_check(release:"3.0", prefix:"webmin-postfix", reference:"0.94-7woody2")) flag++;
if (deb_check(release:"3.0", prefix:"webmin-postgresql", reference:"0.94-7woody2")) flag++;
if (deb_check(release:"3.0", prefix:"webmin-ppp", reference:"0.94-7woody2")) flag++;
if (deb_check(release:"3.0", prefix:"webmin-qmailadmin", reference:"0.94-7woody2")) flag++;
if (deb_check(release:"3.0", prefix:"webmin-quota", reference:"0.94-7woody2")) flag++;
if (deb_check(release:"3.0", prefix:"webmin-raid", reference:"0.94-7woody2")) flag++;
if (deb_check(release:"3.0", prefix:"webmin-samba", reference:"0.94-7woody2")) flag++;
if (deb_check(release:"3.0", prefix:"webmin-sendmail", reference:"0.94-7woody2")) flag++;
if (deb_check(release:"3.0", prefix:"webmin-software", reference:"0.94-7woody2")) flag++;
if (deb_check(release:"3.0", prefix:"webmin-squid", reference:"0.94-7woody2")) flag++;
if (deb_check(release:"3.0", prefix:"webmin-sshd", reference:"0.94-7woody2")) flag++;
if (deb_check(release:"3.0", prefix:"webmin-ssl", reference:"0.94-7woody2")) flag++;
if (deb_check(release:"3.0", prefix:"webmin-status", reference:"0.94-7woody2")) flag++;
if (deb_check(release:"3.0", prefix:"webmin-stunnel", reference:"0.94-7woody2")) flag++;
if (deb_check(release:"3.0", prefix:"webmin-wuftpd", reference:"0.94-7woody2")) flag++;
if (deb_check(release:"3.0", prefix:"webmin-xinetd", reference:"0.94-7woody2")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:deb_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
