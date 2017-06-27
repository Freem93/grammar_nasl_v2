#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Debian Security Advisory DSA-2844. The text 
# itself is copyright (C) Software in the Public Interest, Inc.
#

include("compat.inc");

if (description)
{
  script_id(71980);
  script_version("$Revision: 1.3 $");
  script_cvs_date("$Date: 2015/02/16 15:43:10 $");

  script_cve_id("CVE-2012-6535");
  script_bugtraq_id(58610);
  script_osvdb_id(91521);
  script_xref(name:"DSA", value:"2844");

  script_name(english:"Debian DSA-2844-1 : djvulibre - arbitrary code execution");
  script_summary(english:"Checks dpkg output for the updated package");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Debian host is missing a security-related update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"It was discovered that djvulibre, the Open Source DjVu implementation
project, can be crashed or possibly make it execute arbitrary code
when processing a specially crafted djvu file."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://packages.debian.org/source/squeeze/djvulibre"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.debian.org/security/2014/dsa-2844"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"Upgrade the djvulibre packages.

For the oldstable distribution (squeeze), this problem has been fixed
in version 3.5.23-3+squeeze1.

This problem has been fixed before the release of the stable
distribution (wheezy), therefore it is not affected."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:djvulibre");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:6.0");

  script_set_attribute(attribute:"patch_publication_date", value:"2014/01/15");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/01/16");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2014-2015 Tenable Network Security, Inc.");
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
if (deb_check(release:"6.0", prefix:"djview", reference:"3.5.23-3+squeeze1")) flag++;
if (deb_check(release:"6.0", prefix:"djview3", reference:"3.5.23-3+squeeze1")) flag++;
if (deb_check(release:"6.0", prefix:"djvulibre-bin", reference:"3.5.23-3+squeeze1")) flag++;
if (deb_check(release:"6.0", prefix:"djvulibre-dbg", reference:"3.5.23-3+squeeze1")) flag++;
if (deb_check(release:"6.0", prefix:"djvulibre-desktop", reference:"3.5.23-3+squeeze1")) flag++;
if (deb_check(release:"6.0", prefix:"djvulibre-plugin", reference:"3.5.23-3+squeeze1")) flag++;
if (deb_check(release:"6.0", prefix:"djvuserve", reference:"3.5.23-3+squeeze1")) flag++;
if (deb_check(release:"6.0", prefix:"libdjvulibre-dev", reference:"3.5.23-3+squeeze1")) flag++;
if (deb_check(release:"6.0", prefix:"libdjvulibre-text", reference:"3.5.23-3+squeeze1")) flag++;
if (deb_check(release:"6.0", prefix:"libdjvulibre21", reference:"3.5.23-3+squeeze1")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:deb_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
