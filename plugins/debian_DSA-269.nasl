#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Debian Security Advisory DSA-269. The text 
# itself is copyright (C) Software in the Public Interest, Inc.
#

include("compat.inc");

if (description)
{
  script_id(15106);
  script_version("$Revision: 1.18 $");
  script_cvs_date("$Date: 2013/05/18 00:07:14 $");

  script_cve_id("CVE-2003-0138");
  script_xref(name:"CERT", value:"623217");
  script_xref(name:"DSA", value:"269");

  script_name(english:"Debian DSA-269-1 : heimdal - Cryptographic weakness");
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
Kerberos authentication infrastructure.

This version of the heimdal package changes the default behavior and
disallows cross-realm authentication for Kerberos version 4. Because
of the fundamental nature of the problem, cross-realm authentication
in Kerberos version 4 cannot be made secure and sites should avoid its
use. A new option (--kerberos4-cross-realm) is provided to the kdc
command to re-enable version 4 cross-realm authentication for those
sites that must use this functionality but desire the other security
fixes."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.debian.org/security/2003/dsa-269"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"Upgrade the heimdal packages immediately.

For the stable distribution (woody) this problem has been fixed in
version 0.4e-7.woody.8.

The old stable distribution (potato) is not affected by this problem,
since it isn't compiled against kerberos 4."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:heimdal");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:3.0");

  script_set_attribute(attribute:"patch_publication_date", value:"2003/03/26");
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
if (deb_check(release:"3.0", prefix:"heimdal-clients", reference:"0.4e-7.woody.8")) flag++;
if (deb_check(release:"3.0", prefix:"heimdal-clients-x", reference:"0.4e-7.woody.8")) flag++;
if (deb_check(release:"3.0", prefix:"heimdal-dev", reference:"0.4e-7.woody.8")) flag++;
if (deb_check(release:"3.0", prefix:"heimdal-docs", reference:"0.4e-7.woody.8")) flag++;
if (deb_check(release:"3.0", prefix:"heimdal-kdc", reference:"0.4e-7.woody.8")) flag++;
if (deb_check(release:"3.0", prefix:"heimdal-lib", reference:"0.4e-7.woody.8")) flag++;
if (deb_check(release:"3.0", prefix:"heimdal-servers", reference:"0.4e-7.woody.8")) flag++;
if (deb_check(release:"3.0", prefix:"heimdal-servers-x", reference:"0.4e-7.woody.8")) flag++;
if (deb_check(release:"3.0", prefix:"libasn1-5-heimdal", reference:"0.4e-7.woody.8")) flag++;
if (deb_check(release:"3.0", prefix:"libcomerr1-heimdal", reference:"0.4e-7.woody.8")) flag++;
if (deb_check(release:"3.0", prefix:"libgssapi1-heimdal", reference:"0.4e-7.woody.8")) flag++;
if (deb_check(release:"3.0", prefix:"libhdb7-heimdal", reference:"0.4e-7.woody.8")) flag++;
if (deb_check(release:"3.0", prefix:"libkadm5clnt4-heimdal", reference:"0.4e-7.woody.8")) flag++;
if (deb_check(release:"3.0", prefix:"libkadm5srv7-heimdal", reference:"0.4e-7.woody.8")) flag++;
if (deb_check(release:"3.0", prefix:"libkafs0-heimdal", reference:"0.4e-7.woody.8")) flag++;
if (deb_check(release:"3.0", prefix:"libkrb5-17-heimdal", reference:"0.4e-7.woody.8")) flag++;
if (deb_check(release:"3.0", prefix:"libotp0-heimdal", reference:"0.4e-7.woody.8")) flag++;
if (deb_check(release:"3.0", prefix:"libroken9-heimdal", reference:"0.4e-7.woody.8")) flag++;
if (deb_check(release:"3.0", prefix:"libsl0-heimdal", reference:"0.4e-7.woody.8")) flag++;
if (deb_check(release:"3.0", prefix:"libss0-heimdal", reference:"0.4e-7.woody.8")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:deb_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
