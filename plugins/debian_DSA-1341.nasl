#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Debian Security Advisory DSA-1341. The text 
# itself is copyright (C) Software in the Public Interest, Inc.
#

include("compat.inc");

if (description)
{
  script_id(25851);
  script_version("$Revision: 1.14 $");
  script_cvs_date("$Date: 2013/05/17 23:41:28 $");

  script_cve_id("CVE-2007-2926");
  script_xref(name:"DSA", value:"1341");

  script_name(english:"Debian DSA-1341-2 : bind9 - design error");
  script_summary(english:"Checks dpkg output for the updated package");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Debian host is missing a security-related update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"This update provides fixed packages for the oldstable distribution
(sarge). For reference the original advisory text :

  Amit Klein discovered that the BIND name server generates
  predictable DNS query IDs, which may lead to cache poisoning
  attacks."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.debian.org/security/2007/dsa-1341"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"Upgrade the BIND packages.

For the oldstable distribution (sarge) this problem has been fixed in
version 9.2.4-1sarge3. An update for mips, powerpc and hppa is not yet
available, they will be released soon.

For the stable distribution (etch) this problem has been fixed in
version 9.3.4-2etch1. An update for mips is not yet available, it will
be released soon."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:P/A:N");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:bind9");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:3.1");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:4.0");

  script_set_attribute(attribute:"patch_publication_date", value:"2007/07/25");
  script_set_attribute(attribute:"plugin_publication_date", value:"2007/08/13");
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
if (deb_check(release:"3.1", prefix:"bind9", reference:"9.2.4-1sarge3")) flag++;
if (deb_check(release:"3.1", prefix:"bind9-doc", reference:"9.2.4-1sarge3")) flag++;
if (deb_check(release:"3.1", prefix:"bind9-host", reference:"9.2.4-1sarge3")) flag++;
if (deb_check(release:"3.1", prefix:"dnsutils", reference:"9.2.4-1sarge3")) flag++;
if (deb_check(release:"3.1", prefix:"libbind-dev", reference:"9.2.4-1sarge3")) flag++;
if (deb_check(release:"3.1", prefix:"libdns16", reference:"9.2.4-1sarge3")) flag++;
if (deb_check(release:"3.1", prefix:"libisc7", reference:"9.2.4-1sarge3")) flag++;
if (deb_check(release:"3.1", prefix:"libisccc0", reference:"9.2.4-1sarge3")) flag++;
if (deb_check(release:"3.1", prefix:"libisccfg0", reference:"9.2.4-1sarge3")) flag++;
if (deb_check(release:"3.1", prefix:"liblwres1", reference:"9.2.4-1sarge3")) flag++;
if (deb_check(release:"3.1", prefix:"lwresd", reference:"9.2.4-1sarge3")) flag++;
if (deb_check(release:"4.0", prefix:"bind9", reference:"9.3.4-2etch1")) flag++;
if (deb_check(release:"4.0", prefix:"bind9-doc", reference:"9.3.4-2etch1")) flag++;
if (deb_check(release:"4.0", prefix:"bind9-host", reference:"9.3.4-2etch1")) flag++;
if (deb_check(release:"4.0", prefix:"dnsutils", reference:"9.3.4-2etch1")) flag++;
if (deb_check(release:"4.0", prefix:"libbind-dev", reference:"9.3.4-2etch1")) flag++;
if (deb_check(release:"4.0", prefix:"libbind9-0", reference:"9.3.4-2etch1")) flag++;
if (deb_check(release:"4.0", prefix:"libdns22", reference:"9.3.4-2etch1")) flag++;
if (deb_check(release:"4.0", prefix:"libisc11", reference:"9.3.4-2etch1")) flag++;
if (deb_check(release:"4.0", prefix:"libisccc0", reference:"9.3.4-2etch1")) flag++;
if (deb_check(release:"4.0", prefix:"libisccfg1", reference:"9.3.4-2etch1")) flag++;
if (deb_check(release:"4.0", prefix:"liblwres9", reference:"9.3.4-2etch1")) flag++;
if (deb_check(release:"4.0", prefix:"lwresd", reference:"9.3.4-2etch1")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:deb_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
