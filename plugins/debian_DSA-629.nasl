#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Debian Security Advisory DSA-629. The text 
# itself is copyright (C) Software in the Public Interest, Inc.
#

include("compat.inc");

if (description)
{
  script_id(16112);
  script_version("$Revision: 1.18 $");
  script_cvs_date("$Date: 2013/05/18 00:15:57 $");

  script_cve_id("CVE-2004-1189");
  script_osvdb_id(12533);
  script_xref(name:"CERT", value:"948033");
  script_xref(name:"DSA", value:"629");

  script_name(english:"Debian DSA-629-1 : krb5 - buffer overflow");
  script_summary(english:"Checks dpkg output for the updated package");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Debian host is missing a security-related update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"A buffer overflow has been discovered in the MIT Kerberos 5
administration library (libkadm5srv) that could lead to the execution
of arbitrary code upon exploitation by an authenticated user, not
necessarily one with administrative privileges."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.debian.org/security/2005/dsa-629"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"Upgrade the krb5 packages.

For the stable distribution (woody) this problem has been fixed in
version 1.2.4-5woody7."
  );
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:krb5");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:3.0");

  script_set_attribute(attribute:"patch_publication_date", value:"2005/01/07");
  script_set_attribute(attribute:"plugin_publication_date", value:"2005/01/07");
  script_set_attribute(attribute:"vuln_publication_date", value:"2004/12/20");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2005-2013 Tenable Network Security, Inc.");
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
if (deb_check(release:"3.0", prefix:"krb5-admin-server", reference:"1.2.4-5woody7")) flag++;
if (deb_check(release:"3.0", prefix:"krb5-clients", reference:"1.2.4-5woody7")) flag++;
if (deb_check(release:"3.0", prefix:"krb5-doc", reference:"1.2.4-5woody7")) flag++;
if (deb_check(release:"3.0", prefix:"krb5-ftpd", reference:"1.2.4-5woody7")) flag++;
if (deb_check(release:"3.0", prefix:"krb5-kdc", reference:"1.2.4-5woody7")) flag++;
if (deb_check(release:"3.0", prefix:"krb5-rsh-server", reference:"1.2.4-5woody7")) flag++;
if (deb_check(release:"3.0", prefix:"krb5-telnetd", reference:"1.2.4-5woody7")) flag++;
if (deb_check(release:"3.0", prefix:"krb5-user", reference:"1.2.4-5woody7")) flag++;
if (deb_check(release:"3.0", prefix:"libkadm55", reference:"1.2.4-5woody7")) flag++;
if (deb_check(release:"3.0", prefix:"libkrb5-dev", reference:"1.2.4-5woody7")) flag++;
if (deb_check(release:"3.0", prefix:"libkrb53", reference:"1.2.4-5woody7")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:deb_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
