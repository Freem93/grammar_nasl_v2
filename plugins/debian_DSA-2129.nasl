#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Debian Security Advisory DSA-2129. The text 
# itself is copyright (C) Software in the Public Interest, Inc.
#

include("compat.inc");

if (description)
{
  script_id(50865);
  script_version("$Revision: 1.13 $");
  script_cvs_date("$Date: 2016/12/06 20:25:07 $");

  script_cve_id("CVE-2010-1323");
  script_bugtraq_id(45118);
  script_osvdb_id(69607, 69608, 69609, 69610);
  script_xref(name:"DSA", value:"2129");

  script_name(english:"Debian DSA-2129-1 : krb5 - checksum verification weakness");
  script_summary(english:"Checks dpkg output for the updated package");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Debian host is missing a security-related update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"A vulnerability has been found in krb5, the MIT implementation of
Kerberos.

MIT krb5 clients incorrectly accept unkeyed checksums in the SAM-2
preauthentication challenge: an unauthenticated remote attacker could
alter a SAM-2 challenge, affecting the prompt text seen by the user or
the kind of response sent to the KDC. Under some circumstances, this
can negate the incremental security benefit of using a single-use
authentication mechanism token.

MIT krb5 incorrectly accepts RFC 3961 key-derivation checksums using
RC4 keys when verifying KRB-SAFE messages: an unauthenticated remote
attacker has a 1/256 chance of forging KRB-SAFE messages in an
application protocol if the targeted pre-existing session uses an RC4
session key. Few application protocols use KRB-SAFE messages.

The Common Vulnerabilities and Exposures project has assigned
CVE-2010-1323 to these issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2010-1323"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.debian.org/security/2010/dsa-2129"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"Upgrade the krb5 packages.

For the stable distribution (lenny), these problems have been fixed in
version 1.6.dfsg.4~beta1-5lenny6.

The builds for the mips architecture are not included in this
advisory. They will be released as soon as they are available."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:H/Au:N/C:N/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:U/C:N/I:L/A:N");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:krb5");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:5.0");

  script_set_attribute(attribute:"patch_publication_date", value:"2010/12/01");
  script_set_attribute(attribute:"plugin_publication_date", value:"2010/12/02");
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
if (deb_check(release:"5.0", prefix:"krb5-admin-server", reference:"1.6.dfsg.4~beta1-5lenny6")) flag++;
if (deb_check(release:"5.0", prefix:"krb5-clients", reference:"1.6.dfsg.4~beta1-5lenny6")) flag++;
if (deb_check(release:"5.0", prefix:"krb5-doc", reference:"1.6.dfsg.4~beta1-5lenny6")) flag++;
if (deb_check(release:"5.0", prefix:"krb5-ftpd", reference:"1.6.dfsg.4~beta1-5lenny6")) flag++;
if (deb_check(release:"5.0", prefix:"krb5-kdc", reference:"1.6.dfsg.4~beta1-5lenny6")) flag++;
if (deb_check(release:"5.0", prefix:"krb5-kdc-ldap", reference:"1.6.dfsg.4~beta1-5lenny6")) flag++;
if (deb_check(release:"5.0", prefix:"krb5-pkinit", reference:"1.6.dfsg.4~beta1-5lenny6")) flag++;
if (deb_check(release:"5.0", prefix:"krb5-rsh-server", reference:"1.6.dfsg.4~beta1-5lenny6")) flag++;
if (deb_check(release:"5.0", prefix:"krb5-telnetd", reference:"1.6.dfsg.4~beta1-5lenny6")) flag++;
if (deb_check(release:"5.0", prefix:"krb5-user", reference:"1.6.dfsg.4~beta1-5lenny6")) flag++;
if (deb_check(release:"5.0", prefix:"libkadm55", reference:"1.6.dfsg.4~beta1-5lenny6")) flag++;
if (deb_check(release:"5.0", prefix:"libkrb5-dbg", reference:"1.6.dfsg.4~beta1-5lenny6")) flag++;
if (deb_check(release:"5.0", prefix:"libkrb5-dev", reference:"1.6.dfsg.4~beta1-5lenny6")) flag++;
if (deb_check(release:"5.0", prefix:"libkrb53", reference:"1.6.dfsg.4~beta1-5lenny6")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_note(port:0, extra:deb_report_get());
  else security_note(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
