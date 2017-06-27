#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Debian Security Advisory DSA-773. The text 
# itself is copyright (C) Software in the Public Interest, Inc.
#

if (NASL_LEVEL < 3000) exit(0);

include("compat.inc");

if (description)
{
  script_id(57528);
  script_version("$Revision: 1.3 $");
  script_cvs_date("$Date: 2013/05/18 00:15:58 $");

  script_cve_id("CVE-2005-0392", "CVE-2005-0393", "CVE-2005-0469", "CVE-2005-0753", "CVE-2005-1151", "CVE-2005-1152", "CVE-2005-1174", "CVE-2005-1175", "CVE-2005-1266", "CVE-2005-1269", "CVE-2005-1545", "CVE-2005-1546", "CVE-2005-1686", "CVE-2005-1689", "CVE-2005-1796", "CVE-2005-1848", "CVE-2005-1849", "CVE-2005-1850", "CVE-2005-1851", "CVE-2005-1852", "CVE-2005-1853", "CVE-2005-1858", "CVE-2005-1914", "CVE-2005-1916", "CVE-2005-1922", "CVE-2005-1923", "CVE-2005-1934", "CVE-2005-1992", "CVE-2005-1993", "CVE-2005-2024", "CVE-2005-2040", "CVE-2005-2056", "CVE-2005-2070", "CVE-2005-2096", "CVE-2005-2231", "CVE-2005-2250", "CVE-2005-2277", "CVE-2005-2301", "CVE-2005-2302", "CVE-2005-2370");
  script_osvdb_id(15094, 15670, 16351, 16352, 16686, 16809, 16810, 16811, 16960, 17042, 17236, 17237, 17346, 17390, 17396, 17407, 17449, 17544, 17562, 17632, 17645, 17646, 17722, 17727, 17813, 17827, 17841, 17842, 17843, 17852, 17853, 17892, 18003, 18004, 18071, 18072, 18124, 18126, 18141, 18390);
  script_xref(name:"DSA", value:"773");

  script_name(english:"Debian DSA-773-1 : amd64 - several vulnerabilities");
  script_summary(english:"Checks dpkg output for the updated package");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Debian host is missing a security-related update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"This advisory adds security support for the stable amd64 distribution.
It covers all security updates since the release of sarge, which were
missing updated packages for the not yet official amd64 port. Future
security advisories will include updates for this port as well."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.debian.org/security/2005/dsa-773"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Upgrade the affected several package."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_cwe_id(119);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:several");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:3.1");

  script_set_attribute(attribute:"patch_publication_date", value:"2005/08/11");
  script_set_attribute(attribute:"plugin_publication_date", value:"2012/01/12");
  script_set_attribute(attribute:"vuln_publication_date", value:"2005/03/28");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2012-2013 Tenable Network Security, Inc.");
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
if (deb_check(release:"3.1", prefix:"affix", reference:"2.1.1-2")) flag++;
if (deb_check(release:"3.1", prefix:"centericq", reference:"4.20.0-1sarge1")) flag++;
if (deb_check(release:"3.1", prefix:"centericq-common", reference:"4.20.0-1sarge1")) flag++;
if (deb_check(release:"3.1", prefix:"centericq-fribidi", reference:"4.20.0-1sarge1")) flag++;
if (deb_check(release:"3.1", prefix:"centericq-utf8", reference:"4.20.0-1sarge1")) flag++;
if (deb_check(release:"3.1", prefix:"clamav", reference:"0.84-2.sarge.1")) flag++;
if (deb_check(release:"3.1", prefix:"clamav-daemon", reference:"0.84-2.sarge.1")) flag++;
if (deb_check(release:"3.1", prefix:"clamav-freshclam", reference:"0.84-2.sarge.1")) flag++;
if (deb_check(release:"3.1", prefix:"clamav-milter", reference:"0.84-2.sarge.1")) flag++;
if (deb_check(release:"3.1", prefix:"crip", reference:"3.5-1sarge2")) flag++;
if (deb_check(release:"3.1", prefix:"cvs", reference:"1.11.1p1debian-11")) flag++;
if (deb_check(release:"3.1", prefix:"dhcpcd", reference:"1.3.22pl4-21sarge1")) flag++;
if (deb_check(release:"3.1", prefix:"ekg", reference:"1.5+20050411-5")) flag++;
if (deb_check(release:"3.1", prefix:"ettercap", reference:"0.7.1-1sarge1")) flag++;
if (deb_check(release:"3.1", prefix:"ettercap-common", reference:"0.7.1-1sarge1")) flag++;
if (deb_check(release:"3.1", prefix:"ettercap-gtk", reference:"0.7.1-1sarge1")) flag++;
if (deb_check(release:"3.1", prefix:"fuse-utils", reference:"2.2.1-4sarge2")) flag++;
if (deb_check(release:"3.1", prefix:"gaim", reference:"1.2.1-1.4")) flag++;
if (deb_check(release:"3.1", prefix:"gaim-dev", reference:"1.2.1-1.4")) flag++;
if (deb_check(release:"3.1", prefix:"gedit", reference:"2.8.3-4sarge1")) flag++;
if (deb_check(release:"3.1", prefix:"gopher", reference:"3.0.7sarge1")) flag++;
if (deb_check(release:"3.1", prefix:"heartbeat", reference:"1.2.3-9sarge2")) flag++;
if (deb_check(release:"3.1", prefix:"heartbeat-dev", reference:"1.2.3-9sarge2")) flag++;
if (deb_check(release:"3.1", prefix:"heimdal-clients", reference:"0.6.3-10sarge1")) flag++;
if (deb_check(release:"3.1", prefix:"heimdal-clients-x", reference:"0.6.3-10sarge1")) flag++;
if (deb_check(release:"3.1", prefix:"heimdal-dev", reference:"0.6.3-10sarge1")) flag++;
if (deb_check(release:"3.1", prefix:"heimdal-kdc", reference:"0.6.3-10sarge1")) flag++;
if (deb_check(release:"3.1", prefix:"heimdal-servers", reference:"0.6.3-10sarge1")) flag++;
if (deb_check(release:"3.1", prefix:"heimdal-servers-x", reference:"0.6.3-10sarge1")) flag++;
if (deb_check(release:"3.1", prefix:"ht", reference:"0.8.0-2sarge4")) flag++;
if (deb_check(release:"3.1", prefix:"krb5-admin-server", reference:"1.3.6-2sarge2")) flag++;
if (deb_check(release:"3.1", prefix:"krb5-clients", reference:"1.3.6-2sarge2")) flag++;
if (deb_check(release:"3.1", prefix:"krb5-ftpd", reference:"1.3.6-2sarge2")) flag++;
if (deb_check(release:"3.1", prefix:"krb5-kdc", reference:"1.3.6-2sarge2")) flag++;
if (deb_check(release:"3.1", prefix:"krb5-rsh-server", reference:"1.3.6-2sarge2")) flag++;
if (deb_check(release:"3.1", prefix:"krb5-telnetd", reference:"1.3.6-2sarge2")) flag++;
if (deb_check(release:"3.1", prefix:"krb5-user", reference:"1.3.6-2sarge2")) flag++;
if (deb_check(release:"3.1", prefix:"libaffix-dev", reference:"2.1.1-2")) flag++;
if (deb_check(release:"3.1", prefix:"libaffix2", reference:"2.1.1-2")) flag++;
if (deb_check(release:"3.1", prefix:"libasn1-6-heimdal", reference:"0.6.3-10sarge1")) flag++;
if (deb_check(release:"3.1", prefix:"libclamav-dev", reference:"0.84-2.sarge.1")) flag++;
if (deb_check(release:"3.1", prefix:"libclamav1", reference:"0.84-2.sarge.1")) flag++;
if (deb_check(release:"3.1", prefix:"libdbm-ruby1.8", reference:"1.8.2-7sarge1")) flag++;
if (deb_check(release:"3.1", prefix:"libfuse-dev", reference:"2.2.1-4sarge2")) flag++;
if (deb_check(release:"3.1", prefix:"libfuse2", reference:"2.2.1-4sarge2")) flag++;
if (deb_check(release:"3.1", prefix:"libgadu-dev", reference:"1.5+20050411-5")) flag++;
if (deb_check(release:"3.1", prefix:"libgadu3", reference:"1.5+20050411-5")) flag++;
if (deb_check(release:"3.1", prefix:"libgdbm-ruby1.8", reference:"1.8.2-7sarge1")) flag++;
if (deb_check(release:"3.1", prefix:"libgssapi1-heimdal", reference:"0.6.3-10sarge1")) flag++;
if (deb_check(release:"3.1", prefix:"libhdb7-heimdal", reference:"0.6.3-10sarge1")) flag++;
if (deb_check(release:"3.1", prefix:"libkadm55", reference:"1.3.6-2sarge2")) flag++;
if (deb_check(release:"3.1", prefix:"libkadm5clnt4-heimdal", reference:"0.6.3-10sarge1")) flag++;
if (deb_check(release:"3.1", prefix:"libkadm5srv7-heimdal", reference:"0.6.3-10sarge1")) flag++;
if (deb_check(release:"3.1", prefix:"libkafs0-heimdal", reference:"0.6.3-10sarge1")) flag++;
if (deb_check(release:"3.1", prefix:"libkrb5-17-heimdal", reference:"0.6.3-10sarge1")) flag++;
if (deb_check(release:"3.1", prefix:"libkrb5-dev", reference:"1.3.6-2sarge2")) flag++;
if (deb_check(release:"3.1", prefix:"libkrb53", reference:"1.3.6-2sarge2")) flag++;
if (deb_check(release:"3.1", prefix:"libopenssl-ruby1.8", reference:"1.8.2-7sarge1")) flag++;
if (deb_check(release:"3.1", prefix:"libpils-dev", reference:"1.2.3-9sarge2")) flag++;
if (deb_check(release:"3.1", prefix:"libpils0", reference:"1.2.3-9sarge2")) flag++;
if (deb_check(release:"3.1", prefix:"libreadline-ruby1.8", reference:"1.8.2-7sarge1")) flag++;
if (deb_check(release:"3.1", prefix:"libruby1.8", reference:"1.8.2-7sarge1")) flag++;
if (deb_check(release:"3.1", prefix:"libruby1.8-dbg", reference:"1.8.2-7sarge1")) flag++;
if (deb_check(release:"3.1", prefix:"libstonith-dev", reference:"1.2.3-9sarge2")) flag++;
if (deb_check(release:"3.1", prefix:"libstonith0", reference:"1.2.3-9sarge2")) flag++;
if (deb_check(release:"3.1", prefix:"libtcltk-ruby1.8", reference:"1.8.2-7sarge1")) flag++;
if (deb_check(release:"3.1", prefix:"pdns", reference:"2.9.17-13sarge1")) flag++;
if (deb_check(release:"3.1", prefix:"pdns-backend-geo", reference:"2.9.17-13sarge1")) flag++;
if (deb_check(release:"3.1", prefix:"pdns-backend-ldap", reference:"2.9.17-13sarge1")) flag++;
if (deb_check(release:"3.1", prefix:"pdns-backend-mysql", reference:"2.9.17-13sarge1")) flag++;
if (deb_check(release:"3.1", prefix:"pdns-backend-pgsql", reference:"2.9.17-13sarge1")) flag++;
if (deb_check(release:"3.1", prefix:"pdns-backend-pipe", reference:"2.9.17-13sarge1")) flag++;
if (deb_check(release:"3.1", prefix:"pdns-backend-sqlite", reference:"2.9.17-13sarge1")) flag++;
if (deb_check(release:"3.1", prefix:"pdns-recursor", reference:"2.9.17-13sarge1")) flag++;
if (deb_check(release:"3.1", prefix:"pdns-server", reference:"2.9.17-13sarge1")) flag++;
if (deb_check(release:"3.1", prefix:"ppxp", reference:"0.2001080415-10sarge2")) flag++;
if (deb_check(release:"3.1", prefix:"ppxp-dev", reference:"0.2001080415-10sarge2")) flag++;
if (deb_check(release:"3.1", prefix:"ppxp-tcltk", reference:"0.2001080415-10sarge2")) flag++;
if (deb_check(release:"3.1", prefix:"ppxp-x11", reference:"0.2001080415-10sarge2")) flag++;
if (deb_check(release:"3.1", prefix:"qpopper", reference:"4.0.5-4sarge1")) flag++;
if (deb_check(release:"3.1", prefix:"qpopper-drac", reference:"4.0.5-4sarge1")) flag++;
if (deb_check(release:"3.1", prefix:"razor", reference:"2.670-1sarge2")) flag++;
if (deb_check(release:"3.1", prefix:"ruby1.8", reference:"1.8.2-7sarge1")) flag++;
if (deb_check(release:"3.1", prefix:"ruby1.8-dev", reference:"1.8.2-7sarge1")) flag++;
if (deb_check(release:"3.1", prefix:"spamc", reference:"3.0.3-2")) flag++;
if (deb_check(release:"3.1", prefix:"stonith", reference:"1.2.3-9sarge2")) flag++;
if (deb_check(release:"3.1", prefix:"sudo", reference:"1.6.8p7-1.1sarge1")) flag++;
if (deb_check(release:"3.1", prefix:"zlib-bin", reference:"1.2.2-4.sarge.2")) flag++;
if (deb_check(release:"3.1", prefix:"zlib1g", reference:"1.2.2-4.sarge.2")) flag++;
if (deb_check(release:"3.1", prefix:"zlib1g-dev", reference:"1.2.2-4.sarge.2")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:deb_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
