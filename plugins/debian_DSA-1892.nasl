#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Debian Security Advisory DSA-1892. The text 
# itself is copyright (C) Software in the Public Interest, Inc.
#

include("compat.inc");

if (description)
{
  script_id(44757);
  script_version("$Revision: 1.7 $");
  script_cvs_date("$Date: 2016/05/05 14:49:56 $");

  script_cve_id("CVE-2009-2632", "CVE-2009-3235");
  script_bugtraq_id(36296, 36377);
  script_osvdb_id(57843, 58103);
  script_xref(name:"DSA", value:"1892");

  script_name(english:"Debian DSA-1892-1 : dovecot - buffer overflow");
  script_summary(english:"Checks dpkg output for the updated package");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Debian host is missing a security-related update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"It was discovered that the SIEVE component of dovecot, a mail server
that supports mbox and maildir mailboxes, is vulnerable to a buffer
overflow when processing SIEVE scripts. This can be used to elevate
privileges to the dovecot system user. An attacker who is able to
install SIEVE scripts executed by the server is therefore able to read
and modify arbitrary email messages on the system."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://bugs.debian.org/cgi-bin/bugreport.cgi?bug=546656"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.debian.org/security/2009/dsa-1892"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"Upgrade the dovecot packages.

For the oldstable distribution (etch), this problem has been fixed in
version 1.0.rc15-2etch5.

For the stable distribution (lenny), this problem has been fixed in
version 1:1.0.15-2.3+lenny1."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_cwe_id(119);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:dovecot");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:4.0");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:5.0");

  script_set_attribute(attribute:"patch_publication_date", value:"2009/09/23");
  script_set_attribute(attribute:"plugin_publication_date", value:"2010/02/24");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2010-2016 Tenable Network Security, Inc.");
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
if (deb_check(release:"4.0", prefix:"dovecot-common", reference:"1.0.rc15-2etch5")) flag++;
if (deb_check(release:"4.0", prefix:"dovecot-imapd", reference:"1.0.rc15-2etch5")) flag++;
if (deb_check(release:"4.0", prefix:"dovecot-pop3d", reference:"1.0.rc15-2etch5")) flag++;
if (deb_check(release:"5.0", prefix:"dovecot-common", reference:"1:1.0.15-2.3+lenny1")) flag++;
if (deb_check(release:"5.0", prefix:"dovecot-dev", reference:"1:1.0.15-2.3+lenny1")) flag++;
if (deb_check(release:"5.0", prefix:"dovecot-imapd", reference:"1:1.0.15-2.3+lenny1")) flag++;
if (deb_check(release:"5.0", prefix:"dovecot-pop3d", reference:"1:1.0.15-2.3+lenny1")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:deb_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
