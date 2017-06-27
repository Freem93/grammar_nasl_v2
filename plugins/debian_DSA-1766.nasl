#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Debian Security Advisory DSA-1766. The text 
# itself is copyright (C) Software in the Public Interest, Inc.
#

include("compat.inc");

if (description)
{
  script_id(36120);
  script_version("$Revision: 1.13 $");
  script_cvs_date("$Date: 2016/12/06 20:12:51 $");

  script_cve_id("CVE-2009-0844", "CVE-2009-0845", "CVE-2009-0846", "CVE-2009-0847");
  script_bugtraq_id(34257, 34408, 34409);
  script_xref(name:"DSA", value:"1766");

  script_name(english:"Debian DSA-1766-1 : krb5 - several vulnerabilities");
  script_summary(english:"Checks dpkg output for the updated package");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Debian host is missing a security-related update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Several vulnerabilities have been found in the MIT reference
implementation of Kerberos V5, a system for authenticating users and
services on a network. The Common Vulnerabilities and Exposures
project identified the following problems :

  - CVE-2009-0844
    The Apple Product Security team discovered that the
    SPNEGO GSS-API mechanism suffers of a missing bounds
    check when reading a network input buffer which results
    in an invalid read crashing the application or possibly
    leaking information.

  - CVE-2009-0845
    Under certain conditions the SPNEGO GSS-API mechanism
    references a NULL pointer which crashes the application
    using the library.

  - CVE-2009-0847
    An incorrect length check inside the ASN.1 decoder of
    the MIT krb5 implementation allows an unauthenticated
    remote attacker to crash of the kinit or KDC program.

  - CVE-2009-0846
    Under certain conditions the the ASN.1 decoder of the
    MIT krb5 implementation frees an uninitialized pointer
    which could lead to denial of service and possibly
    arbitrary code execution."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2009-0844"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2009-0845"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2009-0847"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2009-0846"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.debian.org/security/2009/dsa-1766"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"Upgrade the krb5 packages.

For the oldstable distribution (etch), this problem has been fixed in
version 1.4.4-7etch7.

For the stable distribution (lenny), this problem has been fixed in
version 1.6.dfsg.4~beta1-5lenny1."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_cwe_id(20, 119, 189);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:krb5");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:4.0");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:5.0");

  script_set_attribute(attribute:"patch_publication_date", value:"2009/04/09");
  script_set_attribute(attribute:"plugin_publication_date", value:"2009/04/09");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2009-2016 Tenable Network Security, Inc.");
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
if (deb_check(release:"4.0", prefix:"krb5-admin-server", reference:"1.4.4-7etch7")) flag++;
if (deb_check(release:"4.0", prefix:"krb5-clients", reference:"1.4.4-7etch7")) flag++;
if (deb_check(release:"4.0", prefix:"krb5-doc", reference:"1.4.4-7etch7")) flag++;
if (deb_check(release:"4.0", prefix:"krb5-ftpd", reference:"1.4.4-7etch7")) flag++;
if (deb_check(release:"4.0", prefix:"krb5-kdc", reference:"1.4.4-7etch7")) flag++;
if (deb_check(release:"4.0", prefix:"krb5-rsh-server", reference:"1.4.4-7etch7")) flag++;
if (deb_check(release:"4.0", prefix:"krb5-telnetd", reference:"1.4.4-7etch7")) flag++;
if (deb_check(release:"4.0", prefix:"krb5-user", reference:"1.4.4-7etch7")) flag++;
if (deb_check(release:"4.0", prefix:"libkadm55", reference:"1.4.4-7etch7")) flag++;
if (deb_check(release:"4.0", prefix:"libkrb5-dbg", reference:"1.4.4-7etch7")) flag++;
if (deb_check(release:"4.0", prefix:"libkrb5-dev", reference:"1.4.4-7etch7")) flag++;
if (deb_check(release:"4.0", prefix:"libkrb53", reference:"1.4.4-7etch7")) flag++;
if (deb_check(release:"5.0", prefix:"krb5-admin-server", reference:"1.6.dfsg.4~beta1-5lenny1")) flag++;
if (deb_check(release:"5.0", prefix:"krb5-clients", reference:"1.6.dfsg.4~beta1-5lenny1")) flag++;
if (deb_check(release:"5.0", prefix:"krb5-doc", reference:"1.6.dfsg.4~beta1-5lenny1")) flag++;
if (deb_check(release:"5.0", prefix:"krb5-ftpd", reference:"1.6.dfsg.4~beta1-5lenny1")) flag++;
if (deb_check(release:"5.0", prefix:"krb5-kdc", reference:"1.6.dfsg.4~beta1-5lenny1")) flag++;
if (deb_check(release:"5.0", prefix:"krb5-kdc-ldap", reference:"1.6.dfsg.4~beta1-5lenny1")) flag++;
if (deb_check(release:"5.0", prefix:"krb5-pkinit", reference:"1.6.dfsg.4~beta1-5lenny1")) flag++;
if (deb_check(release:"5.0", prefix:"krb5-rsh-server", reference:"1.6.dfsg.4~beta1-5lenny1")) flag++;
if (deb_check(release:"5.0", prefix:"krb5-telnetd", reference:"1.6.dfsg.4~beta1-5lenny1")) flag++;
if (deb_check(release:"5.0", prefix:"krb5-user", reference:"1.6.dfsg.4~beta1-5lenny1")) flag++;
if (deb_check(release:"5.0", prefix:"libkadm55", reference:"1.6.dfsg.4~beta1-5lenny1")) flag++;
if (deb_check(release:"5.0", prefix:"libkrb5-dbg", reference:"1.6.dfsg.4~beta1-5lenny1")) flag++;
if (deb_check(release:"5.0", prefix:"libkrb5-dev", reference:"1.6.dfsg.4~beta1-5lenny1")) flag++;
if (deb_check(release:"5.0", prefix:"libkrb53", reference:"1.6.dfsg.4~beta1-5lenny1")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:deb_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
