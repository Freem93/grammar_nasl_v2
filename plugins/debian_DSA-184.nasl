#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Debian Security Advisory DSA-184. The text 
# itself is copyright (C) Software in the Public Interest, Inc.
#

include("compat.inc");

if (description)
{
  script_id(15021);
  script_version("$Revision: 1.20 $");
  script_cvs_date("$Date: 2014/06/05 10:49:46 $");

  script_cve_id("CVE-2002-1235");
  script_osvdb_id(4870);
  script_xref(name:"CERT", value:"875073");
  script_xref(name:"DSA", value:"184");

  script_name(english:"Debian DSA-184-1 : krb4 - buffer overflow");
  script_summary(english:"Checks dpkg output for the updated package");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Debian host is missing a security-related update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Tom Yu and Sam Hartman of MIT discovered another stack-based buffer
overflow in the kadm_ser_wrap_in function in the Kerberos v4
administration server. This kadmind bug has a working exploit code
circulating, hence it is considered serious."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.debian.org/security/2002/dsa-184"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"Upgrade the krb4 packages immediately.

This problem has been fixed in version 1.1-8-2.2 for the current
stable distribution (woody), in version 1.0-2.2 for the old stable
distribution (potato) and in version 1.1-11-8 for the unstable
distribution (sid)."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:krb4");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:2.2");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:3.0");

  script_set_attribute(attribute:"patch_publication_date", value:"2002/10/30");
  script_set_attribute(attribute:"plugin_publication_date", value:"2004/09/29");
  script_set_attribute(attribute:"vuln_publication_date", value:"2002/10/21");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2004-2014 Tenable Network Security, Inc.");
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
if (deb_check(release:"2.2", prefix:"kerberos4kth-clients", reference:"1.0-2.2")) flag++;
if (deb_check(release:"2.2", prefix:"kerberos4kth-dev", reference:"1.0-2.2")) flag++;
if (deb_check(release:"2.2", prefix:"kerberos4kth-kdc", reference:"1.0-2.2")) flag++;
if (deb_check(release:"2.2", prefix:"kerberos4kth-services", reference:"1.0-2.2")) flag++;
if (deb_check(release:"2.2", prefix:"kerberos4kth-user", reference:"1.0-2.2")) flag++;
if (deb_check(release:"2.2", prefix:"kerberos4kth-x11", reference:"1.0-2.2")) flag++;
if (deb_check(release:"2.2", prefix:"kerberos4kth1", reference:"1.0-2.2")) flag++;
if (deb_check(release:"3.0", prefix:"kerberos4kth-clients", reference:"1.1-8-2.2")) flag++;
if (deb_check(release:"3.0", prefix:"kerberos4kth-clients-x", reference:"1.1-8-2.2")) flag++;
if (deb_check(release:"3.0", prefix:"kerberos4kth-dev", reference:"1.1-8-2.2")) flag++;
if (deb_check(release:"3.0", prefix:"kerberos4kth-dev-common", reference:"1.1-8-2.2")) flag++;
if (deb_check(release:"3.0", prefix:"kerberos4kth-docs", reference:"1.1-8-2.2")) flag++;
if (deb_check(release:"3.0", prefix:"kerberos4kth-kdc", reference:"1.1-8-2.2")) flag++;
if (deb_check(release:"3.0", prefix:"kerberos4kth-kip", reference:"1.1-8-2.2")) flag++;
if (deb_check(release:"3.0", prefix:"kerberos4kth-servers", reference:"1.1-8-2.2")) flag++;
if (deb_check(release:"3.0", prefix:"kerberos4kth-servers-x", reference:"1.1-8-2.2")) flag++;
if (deb_check(release:"3.0", prefix:"kerberos4kth-services", reference:"1.1-8-2.2")) flag++;
if (deb_check(release:"3.0", prefix:"kerberos4kth-user", reference:"1.1-8-2.2")) flag++;
if (deb_check(release:"3.0", prefix:"kerberos4kth-x11", reference:"1.1-8-2.2")) flag++;
if (deb_check(release:"3.0", prefix:"kerberos4kth1", reference:"1.1-8-2.2")) flag++;
if (deb_check(release:"3.0", prefix:"libacl1-kerberos4kth", reference:"1.1-8-2.2")) flag++;
if (deb_check(release:"3.0", prefix:"libkadm1-kerberos4kth", reference:"1.1-8-2.2")) flag++;
if (deb_check(release:"3.0", prefix:"libkdb-1-kerberos4kth", reference:"1.1-8-2.2")) flag++;
if (deb_check(release:"3.0", prefix:"libkrb-1-kerberos4kth", reference:"1.1-8-2.2")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:deb_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
