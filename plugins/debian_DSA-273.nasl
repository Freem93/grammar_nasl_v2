#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Debian Security Advisory DSA-273. The text 
# itself is copyright (C) Software in the Public Interest, Inc.
#

include("compat.inc");

if (description)
{
  script_id(15110);
  script_version("$Revision: 1.19 $");
  script_cvs_date("$Date: 2013/05/18 00:07:14 $");

  script_cve_id("CVE-2003-0138", "CVE-2003-0139");
  script_xref(name:"CERT", value:"442569");
  script_xref(name:"CERT", value:"623217");
  script_xref(name:"DSA", value:"273");

  script_name(english:"Debian DSA-273-1 : krb4 - Cryptographic weakness");
  script_summary(english:"Checks dpkg output for the updated package");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Debian host is missing a security-related update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"A cryptographic weakness in version 4 of the Kerberos protocol allows
an attacker to use a chosen-plaintext attack to impersonate any
principal in a realm. Additional cryptographic weaknesses in the krb4
implementation permit the use of cut-and-paste attacks to fabricate
krb4 tickets for unauthorized client principals if triple-DES keys are
used to key krb4 services. These attacks can subvert a site's entire
Kerberos authentication infrastructure."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.debian.org/security/2003/dsa-273"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"Upgrade the krb4 packages immediately.

For the stable distribution (woody) this problem has been fixed in
version 1.1-8-2.3.

For the old stable distribution (potato) this problem has been fixed
in version 1.0-2.3."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:krb4");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:2.2");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:3.0");

  script_set_attribute(attribute:"patch_publication_date", value:"2003/03/28");
  script_set_attribute(attribute:"plugin_publication_date", value:"2004/09/29");
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
if (deb_check(release:"2.2", prefix:"kerberos4kth-clients", reference:"1.0-2.3")) flag++;
if (deb_check(release:"2.2", prefix:"kerberos4kth-dev", reference:"1.0-2.3")) flag++;
if (deb_check(release:"2.2", prefix:"kerberos4kth-kdc", reference:"1.0-2.3")) flag++;
if (deb_check(release:"2.2", prefix:"kerberos4kth-services", reference:"1.0-2.3")) flag++;
if (deb_check(release:"2.2", prefix:"kerberos4kth-user", reference:"1.0-2.3")) flag++;
if (deb_check(release:"2.2", prefix:"kerberos4kth-x11", reference:"1.0-2.3")) flag++;
if (deb_check(release:"2.2", prefix:"kerberos4kth1", reference:"1.0-2.3")) flag++;
if (deb_check(release:"3.0", prefix:"kerberos4kth-clients", reference:"1.1-8-2.3")) flag++;
if (deb_check(release:"3.0", prefix:"kerberos4kth-clients-x", reference:"1.1-8-2.3")) flag++;
if (deb_check(release:"3.0", prefix:"kerberos4kth-dev", reference:"1.1-8-2.3")) flag++;
if (deb_check(release:"3.0", prefix:"kerberos4kth-dev-common", reference:"1.1-8-2.3")) flag++;
if (deb_check(release:"3.0", prefix:"kerberos4kth-docs", reference:"1.1-8-2.3")) flag++;
if (deb_check(release:"3.0", prefix:"kerberos4kth-kdc", reference:"1.1-8-2.3")) flag++;
if (deb_check(release:"3.0", prefix:"kerberos4kth-kip", reference:"1.1-8-2.3")) flag++;
if (deb_check(release:"3.0", prefix:"kerberos4kth-servers", reference:"1.1-8-2.3")) flag++;
if (deb_check(release:"3.0", prefix:"kerberos4kth-servers-x", reference:"1.1-8-2.3")) flag++;
if (deb_check(release:"3.0", prefix:"kerberos4kth-services", reference:"1.1-8-2.3")) flag++;
if (deb_check(release:"3.0", prefix:"kerberos4kth-user", reference:"1.1-8-2.3")) flag++;
if (deb_check(release:"3.0", prefix:"kerberos4kth-x11", reference:"1.1-8-2.3")) flag++;
if (deb_check(release:"3.0", prefix:"kerberos4kth1", reference:"1.1-8-2.3")) flag++;
if (deb_check(release:"3.0", prefix:"libacl1-kerberos4kth", reference:"1.1-8-2.3")) flag++;
if (deb_check(release:"3.0", prefix:"libkadm1-kerberos4kth", reference:"1.1-8-2.3")) flag++;
if (deb_check(release:"3.0", prefix:"libkdb-1-kerberos4kth", reference:"1.1-8-2.3")) flag++;
if (deb_check(release:"3.0", prefix:"libkrb-1-kerberos4kth", reference:"1.1-8-2.3")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:deb_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
