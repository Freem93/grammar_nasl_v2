#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Debian Security Advisory DSA-2462. The text 
# itself is copyright (C) Software in the Public Interest, Inc.
#

include("compat.inc");

if (description)
{
  script_id(58908);
  script_version("$Revision: 1.8 $");
  script_cvs_date("$Date: 2015/02/16 15:37:38 $");

  script_cve_id("CVE-2012-0259", "CVE-2012-0260", "CVE-2012-1185", "CVE-2012-1186", "CVE-2012-1610", "CVE-2012-1798");
  script_bugtraq_id(51957, 52898);
  script_osvdb_id(80555, 80556, 81021, 81022, 81023, 81024);
  script_xref(name:"DSA", value:"2462");

  script_name(english:"Debian DSA-2462-2 : imagemagick - several vulnerabilities");
  script_summary(english:"Checks dpkg output for the updated package");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Debian host is missing a security-related update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Several integer overflows and missing input validations were
discovered in the ImageMagick image manipulation suite, resulting in
the execution of arbitrary code or denial of service."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://packages.debian.org/source/squeeze/imagemagick"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.debian.org/security/2012/dsa-2462"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"Upgrade the imagemagick packages.

For the stable distribution (squeeze), this problem has been fixed in
version 6.6.0.4-3+squeeze3."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:imagemagick");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:6.0");

  script_set_attribute(attribute:"patch_publication_date", value:"2012/05/03");
  script_set_attribute(attribute:"plugin_publication_date", value:"2012/04/30");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2012-2015 Tenable Network Security, Inc.");
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
if (deb_check(release:"6.0", prefix:"imagemagick", reference:"6.6.0.4-3+squeeze3")) flag++;
if (deb_check(release:"6.0", prefix:"imagemagick-dbg", reference:"6.6.0.4-3+squeeze3")) flag++;
if (deb_check(release:"6.0", prefix:"imagemagick-doc", reference:"6.6.0.4-3+squeeze3")) flag++;
if (deb_check(release:"6.0", prefix:"libmagick++-dev", reference:"6.6.0.4-3+squeeze3")) flag++;
if (deb_check(release:"6.0", prefix:"libmagick++3", reference:"6.6.0.4-3+squeeze3")) flag++;
if (deb_check(release:"6.0", prefix:"libmagickcore-dev", reference:"6.6.0.4-3+squeeze3")) flag++;
if (deb_check(release:"6.0", prefix:"libmagickcore3", reference:"6.6.0.4-3+squeeze3")) flag++;
if (deb_check(release:"6.0", prefix:"libmagickcore3-extra", reference:"6.6.0.4-3+squeeze3")) flag++;
if (deb_check(release:"6.0", prefix:"libmagickwand-dev", reference:"6.6.0.4-3+squeeze3")) flag++;
if (deb_check(release:"6.0", prefix:"libmagickwand3", reference:"6.6.0.4-3+squeeze3")) flag++;
if (deb_check(release:"6.0", prefix:"perlmagick", reference:"6.6.0.4-3+squeeze3")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:deb_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
