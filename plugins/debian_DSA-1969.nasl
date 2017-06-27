#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Debian Security Advisory DSA-1969. The text 
# itself is copyright (C) Software in the Public Interest, Inc.
#

include("compat.inc");

if (description)
{
  script_id(44834);
  script_version("$Revision: 1.7 $");
  script_cvs_date("$Date: 2016/05/05 14:49:56 $");

  script_cve_id("CVE-2009-4212");
  script_bugtraq_id(37749);
  script_xref(name:"DSA", value:"1969");

  script_name(english:"Debian DSA-1969-1 : krb5 - integer underflow");
  script_summary(english:"Checks dpkg output for the updated package");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Debian host is missing a security-related update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"It was discovered that krb5, a system for authenticating users and
services on a network, is prone to integer underflow in the AES and
RC4 decryption operations of the crypto library. A remote attacker can
cause crashes, heap corruption, or, under extraordinarily unlikely
conditions, arbitrary code execution."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.debian.org/security/2010/dsa-1969"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"Upgrade the krb5 package.

For the old stable distribution (etch), this problem has been fixed in
version 1.4.4-7etch8.

For the stable distribution (lenny), this problem has been fixed in
version 1.6.dfsg.4~beta1-5lenny2."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_cwe_id(189);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:krb5");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:4.0");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:5.0");

  script_set_attribute(attribute:"patch_publication_date", value:"2010/01/12");
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
if (deb_check(release:"4.0", prefix:"krb5-admin-server", reference:"1.4.4-7etch8")) flag++;
if (deb_check(release:"4.0", prefix:"krb5-clients", reference:"1.4.4-7etch8")) flag++;
if (deb_check(release:"4.0", prefix:"krb5-doc", reference:"1.4.4-7etch8")) flag++;
if (deb_check(release:"4.0", prefix:"krb5-ftpd", reference:"1.4.4-7etch8")) flag++;
if (deb_check(release:"4.0", prefix:"krb5-kdc", reference:"1.4.4-7etch8")) flag++;
if (deb_check(release:"4.0", prefix:"krb5-rsh-server", reference:"1.4.4-7etch8")) flag++;
if (deb_check(release:"4.0", prefix:"krb5-telnetd", reference:"1.4.4-7etch8")) flag++;
if (deb_check(release:"4.0", prefix:"krb5-user", reference:"1.4.4-7etch8")) flag++;
if (deb_check(release:"4.0", prefix:"libkadm55", reference:"1.4.4-7etch8")) flag++;
if (deb_check(release:"4.0", prefix:"libkrb5-dbg", reference:"1.4.4-7etch8")) flag++;
if (deb_check(release:"4.0", prefix:"libkrb5-dev", reference:"1.4.4-7etch8")) flag++;
if (deb_check(release:"4.0", prefix:"libkrb53", reference:"1.4.4-7etch8")) flag++;
if (deb_check(release:"5.0", prefix:"krb5-admin-server", reference:"1.6.dfsg.4~beta1-5lenny2")) flag++;
if (deb_check(release:"5.0", prefix:"krb5-clients", reference:"1.6.dfsg.4~beta1-5lenny2")) flag++;
if (deb_check(release:"5.0", prefix:"krb5-doc", reference:"1.6.dfsg.4~beta1-5lenny2")) flag++;
if (deb_check(release:"5.0", prefix:"krb5-ftpd", reference:"1.6.dfsg.4~beta1-5lenny2")) flag++;
if (deb_check(release:"5.0", prefix:"krb5-kdc", reference:"1.6.dfsg.4~beta1-5lenny2")) flag++;
if (deb_check(release:"5.0", prefix:"krb5-kdc-ldap", reference:"1.6.dfsg.4~beta1-5lenny2")) flag++;
if (deb_check(release:"5.0", prefix:"krb5-pkinit", reference:"1.6.dfsg.4~beta1-5lenny2")) flag++;
if (deb_check(release:"5.0", prefix:"krb5-rsh-server", reference:"1.6.dfsg.4~beta1-5lenny2")) flag++;
if (deb_check(release:"5.0", prefix:"krb5-telnetd", reference:"1.6.dfsg.4~beta1-5lenny2")) flag++;
if (deb_check(release:"5.0", prefix:"krb5-user", reference:"1.6.dfsg.4~beta1-5lenny2")) flag++;
if (deb_check(release:"5.0", prefix:"libkadm55", reference:"1.6.dfsg.4~beta1-5lenny2")) flag++;
if (deb_check(release:"5.0", prefix:"libkrb5-dbg", reference:"1.6.dfsg.4~beta1-5lenny2")) flag++;
if (deb_check(release:"5.0", prefix:"libkrb5-dev", reference:"1.6.dfsg.4~beta1-5lenny2")) flag++;
if (deb_check(release:"5.0", prefix:"libkrb53", reference:"1.6.dfsg.4~beta1-5lenny2")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:deb_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
