#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Debian Security Advisory DSA-3828. The text 
# itself is copyright (C) Software in the Public Interest, Inc.
#

include("compat.inc");

if (description)
{
  script_id(99292);
  script_version("$Revision: 3.2 $");
  script_cvs_date("$Date: 2017/04/14 18:41:29 $");

  script_cve_id("CVE-2017-2669");
  script_osvdb_id(155237);
  script_xref(name:"DSA", value:"3828");

  script_name(english:"Debian DSA-3828-1 : dovecot - security update");
  script_summary(english:"Checks dpkg output for the updated package");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Debian host is missing a security-related update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"It was discovered that the Dovecot email server is vulnerable to a
denial of service attack. When the 'dict' passdb and userdb are used
for user authentication, the username sent by the IMAP/POP3 client is
sent through var_expand() to perform %variable expansion. Sending
specially crafted %variable fields could result in excessive memory
usage causing the process to crash (and restart)."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://bugs.debian.org/cgi-bin/bugreport.cgi?bug=860049"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://packages.debian.org/source/jessie/dovecot"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.debian.org/security/2017/dsa-3828"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"Upgrade the dovecot packages.

For the stable distribution (jessie), this problem has been fixed in
version 1:2.2.13-12~deb8u2."
  );
  script_set_attribute(attribute:"risk_factor", value:"High");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:dovecot");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:8.0");

  script_set_attribute(attribute:"patch_publication_date", value:"2017/04/10");
  script_set_attribute(attribute:"plugin_publication_date", value:"2017/04/12");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2017 Tenable Network Security, Inc.");
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
if (deb_check(release:"8.0", prefix:"dovecot-core", reference:"1:2.2.13-12~deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"dovecot-dbg", reference:"1:2.2.13-12~deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"dovecot-dev", reference:"1:2.2.13-12~deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"dovecot-gssapi", reference:"1:2.2.13-12~deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"dovecot-imapd", reference:"1:2.2.13-12~deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"dovecot-ldap", reference:"1:2.2.13-12~deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"dovecot-lmtpd", reference:"1:2.2.13-12~deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"dovecot-lucene", reference:"1:2.2.13-12~deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"dovecot-managesieved", reference:"1:2.2.13-12~deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"dovecot-mysql", reference:"1:2.2.13-12~deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"dovecot-pgsql", reference:"1:2.2.13-12~deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"dovecot-pop3d", reference:"1:2.2.13-12~deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"dovecot-sieve", reference:"1:2.2.13-12~deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"dovecot-solr", reference:"1:2.2.13-12~deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"dovecot-sqlite", reference:"1:2.2.13-12~deb8u2")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:deb_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
