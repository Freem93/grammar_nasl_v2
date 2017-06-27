#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Debian Security Advisory DSA-3762. The text 
# itself is copyright (C) Software in the Public Interest, Inc.
#

if (NASL_LEVEL < 3000) exit(0);

include("compat.inc");

if (description)
{
  script_id(96495);
  script_version("$Revision: 3.4 $");
  script_cvs_date("$Date: 2017/03/08 15:07:20 $");

  script_cve_id("CVE-2016-10092", "CVE-2016-10093", "CVE-2016-10094", "CVE-2016-3622", "CVE-2016-3623", "CVE-2016-3624", "CVE-2016-3945", "CVE-2016-3990", "CVE-2016-3991", "CVE-2016-5314", "CVE-2016-5315", "CVE-2016-5316", "CVE-2016-5317", "CVE-2016-5320", "CVE-2016-5321", "CVE-2016-5322", "CVE-2016-5323", "CVE-2016-5652", "CVE-2016-5875", "CVE-2016-6223", "CVE-2016-9273", "CVE-2016-9297", "CVE-2016-9448", "CVE-2016-9453", "CVE-2016-9532", "CVE-2016-9533", "CVE-2016-9534", "CVE-2016-9536", "CVE-2016-9537", "CVE-2016-9538", "CVE-2016-9540");
  script_osvdb_id(136741, 136836, 136837, 136839, 137083, 137084, 140006, 140007, 140008, 140009, 140016, 140117, 140118, 141537, 141540, 145021, 145022, 145023, 145728, 145751, 145752, 145753, 147159, 147303, 147314, 147758, 147779, 148165, 148170, 149138);
  script_xref(name:"DSA", value:"3762");

  script_name(english:"Debian DSA-3762-1 : tiff - security update");
  script_summary(english:"Checks dpkg output for the updated package");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Debian host is missing a security-related update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Multiple vulnerabilities have been discovered in the libtiff library
and the included tools tiff2rgba, rgb2ycbcr, tiffcp, tiffcrop,
tiff2pdf and tiffsplit, which may result in denial of service, memory
disclosure or the execution of arbitrary code.

There were additional vulnerabilities in the tools bmp2tiff, gif2tiff,
thumbnail and ras2tiff, but since these were addressed by the libtiff
developers by removing the tools altogether, no patches are available
and those tools were also removed from the tiff package in Debian
stable. The change had already been made in Debian stretch before and
no applications included in Debian are known to rely on these scripts.
If you use those tools in custom setups, consider using a different
conversion/thumbnailing tool."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://packages.debian.org/source/jessie/tiff"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.debian.org/security/2017/dsa-3762"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"Upgrade the tiff packages.

For the stable distribution (jessie), these problems have been fixed
in version 4.0.3-12.3+deb8u2."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:ND");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:tiff");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:8.0");

  script_set_attribute(attribute:"patch_publication_date", value:"2017/01/13");
  script_set_attribute(attribute:"plugin_publication_date", value:"2017/01/16");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2017 Tenable Network Security, Inc.");
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
if (deb_check(release:"8.0", prefix:"libtiff-doc", reference:"4.0.3-12.3+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"libtiff-opengl", reference:"4.0.3-12.3+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"libtiff-tools", reference:"4.0.3-12.3+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"libtiff5", reference:"4.0.3-12.3+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"libtiff5-dev", reference:"4.0.3-12.3+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"libtiffxx5", reference:"4.0.3-12.3+deb8u2")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:deb_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
