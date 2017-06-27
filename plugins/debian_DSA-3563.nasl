#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Debian Security Advisory DSA-3563. The text 
# itself is copyright (C) Software in the Public Interest, Inc.
#

include("compat.inc");

if (description)
{
  script_id(90839);
  script_version("$Revision: 2.4 $");
  script_cvs_date("$Date: 2016/12/06 20:25:08 $");

  script_cve_id("CVE-2015-8868");
  script_osvdb_id(132203);
  script_xref(name:"DSA", value:"3563");

  script_name(english:"Debian DSA-3563-1 : poppler - security update");
  script_summary(english:"Checks dpkg output for the updated package");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Debian host is missing a security-related update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"It was discovered that a heap overflow in the Poppler PDF library may
result in denial of service and potentially the execution of arbitrary
code if a malformed PDF file is opened."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://packages.debian.org/source/jessie/poppler"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.debian.org/security/2016/dsa-3563"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"Upgrade the poppler packages.

For the stable distribution (jessie), this problem has been fixed in
version 0.26.5-2+deb8u1."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:ND");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:F/RL:O/RC:X");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:poppler");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:8.0");

  script_set_attribute(attribute:"patch_publication_date", value:"2016/05/01");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/05/03");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2016 Tenable Network Security, Inc.");
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
if (deb_check(release:"8.0", prefix:"gir1.2-poppler-0.18", reference:"0.26.5-2+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"libpoppler-cpp-dev", reference:"0.26.5-2+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"libpoppler-cpp0", reference:"0.26.5-2+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"libpoppler-dev", reference:"0.26.5-2+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"libpoppler-glib-dev", reference:"0.26.5-2+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"libpoppler-glib-doc", reference:"0.26.5-2+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"libpoppler-glib8", reference:"0.26.5-2+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"libpoppler-private-dev", reference:"0.26.5-2+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"libpoppler-qt4-4", reference:"0.26.5-2+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"libpoppler-qt4-dev", reference:"0.26.5-2+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"libpoppler-qt5-1", reference:"0.26.5-2+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"libpoppler-qt5-dev", reference:"0.26.5-2+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"libpoppler46", reference:"0.26.5-2+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"poppler-dbg", reference:"0.26.5-2+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"poppler-utils", reference:"0.26.5-2+deb8u1")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:deb_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
