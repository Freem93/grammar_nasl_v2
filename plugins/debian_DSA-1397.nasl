#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Debian Security Advisory DSA-1397. The text 
# itself is copyright (C) Software in the Public Interest, Inc.
#

include("compat.inc");

if (description)
{
  script_id(27621);
  script_version("$Revision: 1.11 $");
  script_cvs_date("$Date: 2013/05/17 23:45:44 $");

  script_cve_id("CVE-2007-5197");
  script_osvdb_id(41872);
  script_xref(name:"DSA", value:"1397");

  script_name(english:"Debian DSA-1397-1 : mono - integer overflow");
  script_summary(english:"Checks dpkg output for the updated package");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Debian host is missing a security-related update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"An integer overflow in the BigInteger data type implementation has
been discovered in the free .NET runtime Mono.

The oldstable distribution (sarge) doesn't contain mono."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.debian.org/security/2007/dsa-1397"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"Upgrade the mono packages.

For the stable distribution (etch) this problem has been fixed in
version 1.2.2.1-1etch1. A powerpc build will be provided later."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_cwe_id(119);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:mono");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:4.0");

  script_set_attribute(attribute:"patch_publication_date", value:"2007/11/03");
  script_set_attribute(attribute:"plugin_publication_date", value:"2007/11/05");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2007-2013 Tenable Network Security, Inc.");
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
if (deb_check(release:"4.0", prefix:"libmono-accessibility1.0-cil", reference:"1.2.2.1-1etch1")) flag++;
if (deb_check(release:"4.0", prefix:"libmono-accessibility2.0-cil", reference:"1.2.2.1-1etch1")) flag++;
if (deb_check(release:"4.0", prefix:"libmono-bytefx0.7.6.1-cil", reference:"1.2.2.1-1etch1")) flag++;
if (deb_check(release:"4.0", prefix:"libmono-bytefx0.7.6.2-cil", reference:"1.2.2.1-1etch1")) flag++;
if (deb_check(release:"4.0", prefix:"libmono-c5-1.0-cil", reference:"1.2.2.1-1etch1")) flag++;
if (deb_check(release:"4.0", prefix:"libmono-cairo1.0-cil", reference:"1.2.2.1-1etch1")) flag++;
if (deb_check(release:"4.0", prefix:"libmono-cairo2.0-cil", reference:"1.2.2.1-1etch1")) flag++;
if (deb_check(release:"4.0", prefix:"libmono-corlib1.0-cil", reference:"1.2.2.1-1etch1")) flag++;
if (deb_check(release:"4.0", prefix:"libmono-corlib2.0-cil", reference:"1.2.2.1-1etch1")) flag++;
if (deb_check(release:"4.0", prefix:"libmono-cscompmgd7.0-cil", reference:"1.2.2.1-1etch1")) flag++;
if (deb_check(release:"4.0", prefix:"libmono-cscompmgd8.0-cil", reference:"1.2.2.1-1etch1")) flag++;
if (deb_check(release:"4.0", prefix:"libmono-data-tds1.0-cil", reference:"1.2.2.1-1etch1")) flag++;
if (deb_check(release:"4.0", prefix:"libmono-data-tds2.0-cil", reference:"1.2.2.1-1etch1")) flag++;
if (deb_check(release:"4.0", prefix:"libmono-dev", reference:"1.2.2.1-1etch1")) flag++;
if (deb_check(release:"4.0", prefix:"libmono-firebirdsql1.7-cil", reference:"1.2.2.1-1etch1")) flag++;
if (deb_check(release:"4.0", prefix:"libmono-ldap1.0-cil", reference:"1.2.2.1-1etch1")) flag++;
if (deb_check(release:"4.0", prefix:"libmono-ldap2.0-cil", reference:"1.2.2.1-1etch1")) flag++;
if (deb_check(release:"4.0", prefix:"libmono-microsoft-build2.0-cil", reference:"1.2.2.1-1etch1")) flag++;
if (deb_check(release:"4.0", prefix:"libmono-microsoft7.0-cil", reference:"1.2.2.1-1etch1")) flag++;
if (deb_check(release:"4.0", prefix:"libmono-microsoft8.0-cil", reference:"1.2.2.1-1etch1")) flag++;
if (deb_check(release:"4.0", prefix:"libmono-npgsql1.0-cil", reference:"1.2.2.1-1etch1")) flag++;
if (deb_check(release:"4.0", prefix:"libmono-npgsql2.0-cil", reference:"1.2.2.1-1etch1")) flag++;
if (deb_check(release:"4.0", prefix:"libmono-oracle1.0-cil", reference:"1.2.2.1-1etch1")) flag++;
if (deb_check(release:"4.0", prefix:"libmono-oracle2.0-cil", reference:"1.2.2.1-1etch1")) flag++;
if (deb_check(release:"4.0", prefix:"libmono-peapi1.0-cil", reference:"1.2.2.1-1etch1")) flag++;
if (deb_check(release:"4.0", prefix:"libmono-peapi2.0-cil", reference:"1.2.2.1-1etch1")) flag++;
if (deb_check(release:"4.0", prefix:"libmono-relaxng1.0-cil", reference:"1.2.2.1-1etch1")) flag++;
if (deb_check(release:"4.0", prefix:"libmono-relaxng2.0-cil", reference:"1.2.2.1-1etch1")) flag++;
if (deb_check(release:"4.0", prefix:"libmono-security1.0-cil", reference:"1.2.2.1-1etch1")) flag++;
if (deb_check(release:"4.0", prefix:"libmono-security2.0-cil", reference:"1.2.2.1-1etch1")) flag++;
if (deb_check(release:"4.0", prefix:"libmono-sharpzip0.6-cil", reference:"1.2.2.1-1etch1")) flag++;
if (deb_check(release:"4.0", prefix:"libmono-sharpzip0.84-cil", reference:"1.2.2.1-1etch1")) flag++;
if (deb_check(release:"4.0", prefix:"libmono-sharpzip2.6-cil", reference:"1.2.2.1-1etch1")) flag++;
if (deb_check(release:"4.0", prefix:"libmono-sharpzip2.84-cil", reference:"1.2.2.1-1etch1")) flag++;
if (deb_check(release:"4.0", prefix:"libmono-sqlite1.0-cil", reference:"1.2.2.1-1etch1")) flag++;
if (deb_check(release:"4.0", prefix:"libmono-sqlite2.0-cil", reference:"1.2.2.1-1etch1")) flag++;
if (deb_check(release:"4.0", prefix:"libmono-system-data1.0-cil", reference:"1.2.2.1-1etch1")) flag++;
if (deb_check(release:"4.0", prefix:"libmono-system-data2.0-cil", reference:"1.2.2.1-1etch1")) flag++;
if (deb_check(release:"4.0", prefix:"libmono-system-ldap1.0-cil", reference:"1.2.2.1-1etch1")) flag++;
if (deb_check(release:"4.0", prefix:"libmono-system-ldap2.0-cil", reference:"1.2.2.1-1etch1")) flag++;
if (deb_check(release:"4.0", prefix:"libmono-system-messaging1.0-cil", reference:"1.2.2.1-1etch1")) flag++;
if (deb_check(release:"4.0", prefix:"libmono-system-messaging2.0-cil", reference:"1.2.2.1-1etch1")) flag++;
if (deb_check(release:"4.0", prefix:"libmono-system-runtime1.0-cil", reference:"1.2.2.1-1etch1")) flag++;
if (deb_check(release:"4.0", prefix:"libmono-system-runtime2.0-cil", reference:"1.2.2.1-1etch1")) flag++;
if (deb_check(release:"4.0", prefix:"libmono-system-web1.0-cil", reference:"1.2.2.1-1etch1")) flag++;
if (deb_check(release:"4.0", prefix:"libmono-system-web2.0-cil", reference:"1.2.2.1-1etch1")) flag++;
if (deb_check(release:"4.0", prefix:"libmono-system1.0-cil", reference:"1.2.2.1-1etch1")) flag++;
if (deb_check(release:"4.0", prefix:"libmono-system2.0-cil", reference:"1.2.2.1-1etch1")) flag++;
if (deb_check(release:"4.0", prefix:"libmono-winforms1.0-cil", reference:"1.2.2.1-1etch1")) flag++;
if (deb_check(release:"4.0", prefix:"libmono-winforms2.0-cil", reference:"1.2.2.1-1etch1")) flag++;
if (deb_check(release:"4.0", prefix:"libmono0", reference:"1.2.2.1-1etch1")) flag++;
if (deb_check(release:"4.0", prefix:"libmono1.0-cil", reference:"1.2.2.1-1etch1")) flag++;
if (deb_check(release:"4.0", prefix:"libmono2.0-cil", reference:"1.2.2.1-1etch1")) flag++;
if (deb_check(release:"4.0", prefix:"mono", reference:"1.2.2.1-1etch1")) flag++;
if (deb_check(release:"4.0", prefix:"mono-common", reference:"1.2.2.1-1etch1")) flag++;
if (deb_check(release:"4.0", prefix:"mono-devel", reference:"1.2.2.1-1etch1")) flag++;
if (deb_check(release:"4.0", prefix:"mono-gac", reference:"1.2.2.1-1etch1")) flag++;
if (deb_check(release:"4.0", prefix:"mono-gmcs", reference:"1.2.2.1-1etch1")) flag++;
if (deb_check(release:"4.0", prefix:"mono-jay", reference:"1.2.2.1-1etch1")) flag++;
if (deb_check(release:"4.0", prefix:"mono-jit", reference:"1.2.2.1-1etch1")) flag++;
if (deb_check(release:"4.0", prefix:"mono-mcs", reference:"1.2.2.1-1etch1")) flag++;
if (deb_check(release:"4.0", prefix:"mono-mjs", reference:"1.2.2.1-1etch1")) flag++;
if (deb_check(release:"4.0", prefix:"mono-runtime", reference:"1.2.2.1-1etch1")) flag++;
if (deb_check(release:"4.0", prefix:"mono-utils", reference:"1.2.2.1-1etch1")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:deb_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
