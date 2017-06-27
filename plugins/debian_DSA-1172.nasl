#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Debian Security Advisory DSA-1172. The text 
# itself is copyright (C) Software in the Public Interest, Inc.
#

include("compat.inc");

if (description)
{
  script_id(22714);
  script_version("$Revision: 1.14 $");
  script_cvs_date("$Date: 2015/08/31 14:21:56 $");

  script_cve_id("CVE-2006-4095", "CVE-2006-4096");
  script_osvdb_id(28557, 28558);
  script_xref(name:"CERT", value:"697164");
  script_xref(name:"CERT", value:"915404");
  script_xref(name:"DSA", value:"1172");

  script_name(english:"Debian DSA-1172-1 : bind9 - programming error");
  script_summary(english:"Checks dpkg output for the updated package");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Debian host is missing a security-related update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Two vulnerabilities have been discovered in BIND9, the Berkeley
Internet Name Domain server. The first relates to SIG query processing
and the second relates to a condition that can trigger an INSIST
failure, both lead to a denial of service."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.debian.org/security/2006/dsa-1172"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"Upgrade the bind9 package.

For the stable distribution (sarge) these problems have been fixed in
version 9.2.4-1sarge1."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:ND/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:bind9");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:3.1");

  script_set_attribute(attribute:"patch_publication_date", value:"2006/09/09");
  script_set_attribute(attribute:"plugin_publication_date", value:"2006/10/14");
  script_set_attribute(attribute:"vuln_publication_date", value:"2006/09/06");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2006-2015 Tenable Network Security, Inc.");
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
if (deb_check(release:"3.1", prefix:"bind9", reference:"9.2.4-1sarge1")) flag++;
if (deb_check(release:"3.1", prefix:"bind9-doc", reference:"9.2.4-1sarge1")) flag++;
if (deb_check(release:"3.1", prefix:"bind9-host", reference:"9.2.4-1sarge1")) flag++;
if (deb_check(release:"3.1", prefix:"dnsutils", reference:"9.2.4-1sarge1")) flag++;
if (deb_check(release:"3.1", prefix:"libbind-dev", reference:"9.2.4-1sarge1")) flag++;
if (deb_check(release:"3.1", prefix:"libdns16", reference:"9.2.4-1sarge1")) flag++;
if (deb_check(release:"3.1", prefix:"libisc7", reference:"9.2.4-1sarge1")) flag++;
if (deb_check(release:"3.1", prefix:"libisccc0", reference:"9.2.4-1sarge1")) flag++;
if (deb_check(release:"3.1", prefix:"libisccfg0", reference:"9.2.4-1sarge1")) flag++;
if (deb_check(release:"3.1", prefix:"liblwres1", reference:"9.2.4-1sarge1")) flag++;
if (deb_check(release:"3.1", prefix:"lwresd", reference:"9.2.4-1sarge1")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:deb_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
