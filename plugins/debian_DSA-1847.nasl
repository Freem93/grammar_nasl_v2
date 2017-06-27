#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Debian Security Advisory DSA-1847. The text 
# itself is copyright (C) Software in the Public Interest, Inc.
#

include("compat.inc");

if (description)
{
  script_id(44712);
  script_version("$Revision: 1.14 $");
  script_cvs_date("$Date: 2013/05/17 23:54:22 $");

  script_cve_id("CVE-2009-0696");
  script_xref(name:"CERT", value:"725188");
  script_xref(name:"DSA", value:"1847");

  script_name(english:"Debian DSA-1847-1 : bind9 - improper assert");
  script_summary(english:"Checks dpkg output for the updated package");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Debian host is missing a security-related update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"It was discovered that the BIND DNS server terminates when processing
a specially crafted dynamic DNS update. This vulnerability affects all
BIND servers which serve at least one DNS zone authoritatively, as a
master, even if dynamic updates are not enabled. The default Debian
configuration for resolvers includes several authoritative zones, too,
so resolvers are also affected by this issue unless these zones have
been removed."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://bugs.debian.org/cgi-bin/bugreport.cgi?bug=538975"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.debian.org/security/2009/dsa-1847"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"Upgrade the bind9 packages.

For the old stable distribution (etch), this problem has been fixed in
version 9.3.4-2etch5.

For the stable distribution (lenny), this problem has been fixed in
version 9.5.1.dfsg.P3-1."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:N/A:P");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_core", value:"true");
  script_cwe_id(16);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:bind9");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:4.0");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:5.0");

  script_set_attribute(attribute:"patch_publication_date", value:"2009/07/29");
  script_set_attribute(attribute:"plugin_publication_date", value:"2010/02/24");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2010-2013 Tenable Network Security, Inc.");
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
if (deb_check(release:"4.0", prefix:"bind9", reference:"9.3.4-2etch5")) flag++;
if (deb_check(release:"4.0", prefix:"bind9-doc", reference:"9.3.4-2etch5")) flag++;
if (deb_check(release:"4.0", prefix:"bind9-host", reference:"9.3.4-2etch5")) flag++;
if (deb_check(release:"4.0", prefix:"dnsutils", reference:"9.3.4-2etch5")) flag++;
if (deb_check(release:"4.0", prefix:"libbind-dev", reference:"9.3.4-2etch5")) flag++;
if (deb_check(release:"4.0", prefix:"libbind9-0", reference:"9.3.4-2etch5")) flag++;
if (deb_check(release:"4.0", prefix:"libdns22", reference:"9.3.4-2etch5")) flag++;
if (deb_check(release:"4.0", prefix:"libisc11", reference:"9.3.4-2etch5")) flag++;
if (deb_check(release:"4.0", prefix:"libisccc0", reference:"9.3.4-2etch5")) flag++;
if (deb_check(release:"4.0", prefix:"libisccfg1", reference:"9.3.4-2etch5")) flag++;
if (deb_check(release:"4.0", prefix:"liblwres9", reference:"9.3.4-2etch5")) flag++;
if (deb_check(release:"4.0", prefix:"lwresd", reference:"9.3.4-2etch5")) flag++;
if (deb_check(release:"5.0", prefix:"bind9", reference:"9.5.1.dfsg.P3-1")) flag++;
if (deb_check(release:"5.0", prefix:"bind9-doc", reference:"9.5.1.dfsg.P3-1")) flag++;
if (deb_check(release:"5.0", prefix:"bind9-host", reference:"9.5.1.dfsg.P3-1")) flag++;
if (deb_check(release:"5.0", prefix:"bind9utils", reference:"9.5.1.dfsg.P3-1")) flag++;
if (deb_check(release:"5.0", prefix:"dnsutils", reference:"9.5.1.dfsg.P3-1")) flag++;
if (deb_check(release:"5.0", prefix:"libbind-dev", reference:"9.5.1.dfsg.P3-1")) flag++;
if (deb_check(release:"5.0", prefix:"libbind9-40", reference:"9.5.1.dfsg.P3-1")) flag++;
if (deb_check(release:"5.0", prefix:"libdns45", reference:"9.5.1.dfsg.P3-1")) flag++;
if (deb_check(release:"5.0", prefix:"libisc45", reference:"9.5.1.dfsg.P3-1")) flag++;
if (deb_check(release:"5.0", prefix:"libisccc40", reference:"9.5.1.dfsg.P3-1")) flag++;
if (deb_check(release:"5.0", prefix:"libisccfg40", reference:"9.5.1.dfsg.P3-1")) flag++;
if (deb_check(release:"5.0", prefix:"liblwres40", reference:"9.5.1.dfsg.P3-1")) flag++;
if (deb_check(release:"5.0", prefix:"lwresd", reference:"9.5.1.dfsg.P3-1")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:deb_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
