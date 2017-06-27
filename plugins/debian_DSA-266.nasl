#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Debian Security Advisory DSA-266. The text 
# itself is copyright (C) Software in the Public Interest, Inc.
#

include("compat.inc");

if (description)
{
  script_id(15103);
  script_version("$Revision: 1.19 $");
  script_cvs_date("$Date: 2013/05/18 00:07:14 $");

  script_cve_id("CVE-2003-0028", "CVE-2003-0072", "CVE-2003-0082", "CVE-2003-0138", "CVE-2003-0139");
  script_osvdb_id(4901, 4902);
  script_xref(name:"CERT", value:"442569");
  script_xref(name:"CERT", value:"516825");
  script_xref(name:"CERT", value:"623217");
  script_xref(name:"DSA", value:"266");

  script_name(english:"Debian DSA-266-1 : krb5 - several vulnerabilities");
  script_summary(english:"Checks dpkg output for the updated package");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Debian host is missing a security-related update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Several vulnerabilities have been discovered in krb5, an
implementation of MIT Kerberos.

  - A cryptographic weakness in version 4 of the Kerberos
    protocol allows an attacker to use a chosen-plaintext
    attack to impersonate any principal in a realm.
    Additional cryptographic weaknesses in the krb4
    implementation included in the MIT krb5 distribution
    permit the use of cut-and-paste attacks to fabricate
    krb4 tickets for unauthorized client principals if
    triple-DES keys are used to key krb4 services. These
    attacks can subvert a site's entire Kerberos
    authentication infrastructure.
    Kerberos version 5 does not contain this cryptographic
    vulnerability. Sites are not vulnerable if they have
    Kerberos v4 completely disabled, including the disabling
    of any krb5 to krb4 translation services.

  - The MIT Kerberos 5 implementation includes an RPC
    library derived from SUNRPC. The implementation contains
    length checks, that are vulnerable to an integer
    overflow, which may be exploitable to create denials of
    service or to gain unauthorized access to sensitive
    information.
  - Buffer overrun and underrun problems exist in Kerberos
    principal name handling in unusual cases, such as names
    with zero components, names with one empty component, or
    host-based service principal names with no host name
    component.

This version of the krb5 package changes the default behavior and
disallows cross-realm authentication for Kerberos version 4. Because
of the fundamental nature of the problem, cross-realm authentication
in Kerberos version 4 cannot be made secure and sites should avoid its
use. A new option (-X) is provided to the krb5kdc and krb524d commands
to re-enable version 4 cross-realm authentication for those sites that
must use this functionality but desire the other security fixes."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.debian.org/security/2003/dsa-266"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"Upgrade the krb5 package.

For the stable distribution (woody) this problem has been fixed in
version 1.2.4-5woody4.

The old stable distribution (potato) does not contain krb5 packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:krb5");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:3.0");

  script_set_attribute(attribute:"patch_publication_date", value:"2003/03/24");
  script_set_attribute(attribute:"plugin_publication_date", value:"2004/09/29");
  script_set_attribute(attribute:"vuln_publication_date", value:"2003/03/19");
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
if (deb_check(release:"3.0", prefix:"krb5-admin-server", reference:"1.2.4-5woody4")) flag++;
if (deb_check(release:"3.0", prefix:"krb5-clients", reference:"1.2.4-5woody4")) flag++;
if (deb_check(release:"3.0", prefix:"krb5-doc", reference:"1.2.4-5woody4")) flag++;
if (deb_check(release:"3.0", prefix:"krb5-ftpd", reference:"1.2.4-5woody4")) flag++;
if (deb_check(release:"3.0", prefix:"krb5-kdc", reference:"1.2.4-5woody4")) flag++;
if (deb_check(release:"3.0", prefix:"krb5-rsh-server", reference:"1.2.4-5woody4")) flag++;
if (deb_check(release:"3.0", prefix:"krb5-telnetd", reference:"1.2.4-5woody4")) flag++;
if (deb_check(release:"3.0", prefix:"krb5-user", reference:"1.2.4-5woody4")) flag++;
if (deb_check(release:"3.0", prefix:"libkadm55", reference:"1.2.4-5woody4")) flag++;
if (deb_check(release:"3.0", prefix:"libkrb5-dev", reference:"1.2.4-5woody4")) flag++;
if (deb_check(release:"3.0", prefix:"libkrb53", reference:"1.2.4-5woody4")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:deb_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
