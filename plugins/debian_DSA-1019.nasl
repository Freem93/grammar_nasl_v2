#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Debian Security Advisory DSA-1019. The text 
# itself is copyright (C) Software in the Public Interest, Inc.
#

include("compat.inc");

if (description)
{
  script_id(22561);
  script_version("$Revision: 1.11 $");
  script_cvs_date("$Date: 2013/05/17 23:36:51 $");

  script_cve_id("CVE-2006-1244");
  script_bugtraq_id(16748);
  script_osvdb_id(23834);
  script_xref(name:"DSA", value:"1019");

  script_name(english:"Debian DSA-1019-1 : koffice - several vulnerabilities");
  script_summary(english:"Checks dpkg output for the updated package");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Debian host is missing a security-related update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Derek Noonburg has fixed several potential vulnerabilities in xpdf,
the Portable Document Format (PDF) suite, which is also present in
koffice, the KDE Office Suite."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.debian.org/security/2006/dsa-1019"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"Upgrade the koffice packages.

The old stable distribution (woody) does not contain koffice packages.

For the stable distribution (sarge) these problems have been fixed in
version 1.3.5-4.sarge.3."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:H/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:koffice");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:3.1");

  script_set_attribute(attribute:"patch_publication_date", value:"2006/03/24");
  script_set_attribute(attribute:"plugin_publication_date", value:"2006/10/14");
  script_set_attribute(attribute:"vuln_publication_date", value:"2006/03/01");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2006-2013 Tenable Network Security, Inc.");
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
if (deb_check(release:"3.1", prefix:"karbon", reference:"1.3.5-4.sarge.3")) flag++;
if (deb_check(release:"3.1", prefix:"kchart", reference:"1.3.5-4.sarge.3")) flag++;
if (deb_check(release:"3.1", prefix:"kformula", reference:"1.3.5-4.sarge.3")) flag++;
if (deb_check(release:"3.1", prefix:"kivio", reference:"1.3.5-4.sarge.3")) flag++;
if (deb_check(release:"3.1", prefix:"kivio-data", reference:"1.3.5-4.sarge.3")) flag++;
if (deb_check(release:"3.1", prefix:"koffice", reference:"1.3.5-4.sarge.3")) flag++;
if (deb_check(release:"3.1", prefix:"koffice-data", reference:"1.3.5-4.sarge.3")) flag++;
if (deb_check(release:"3.1", prefix:"koffice-dev", reference:"1.3.5-4.sarge.3")) flag++;
if (deb_check(release:"3.1", prefix:"koffice-doc-html", reference:"1.3.5-4.sarge.3")) flag++;
if (deb_check(release:"3.1", prefix:"koffice-libs", reference:"1.3.5-4.sarge.3")) flag++;
if (deb_check(release:"3.1", prefix:"koshell", reference:"1.3.5-4.sarge.3")) flag++;
if (deb_check(release:"3.1", prefix:"kpresenter", reference:"1.3.5-4.sarge.3")) flag++;
if (deb_check(release:"3.1", prefix:"kspread", reference:"1.3.5-4.sarge.3")) flag++;
if (deb_check(release:"3.1", prefix:"kugar", reference:"1.3.5-4.sarge.3")) flag++;
if (deb_check(release:"3.1", prefix:"kword", reference:"1.3.5-4.sarge.3")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:deb_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
