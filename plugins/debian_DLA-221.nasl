#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Debian Security Advisory DLA-221-1. The text
# itself is copyright (C) Software in the Public Interest, Inc.
#

include("compat.inc");

if (description)
{
  script_id(83499);
  script_version("$Revision: 2.7 $");
  script_cvs_date("$Date: 2016/12/06 20:03:50 $");

  script_cve_id("CVE-2014-8128", "CVE-2014-8129", "CVE-2014-9330", "CVE-2014-9655");
  script_bugtraq_id(71789, 72326, 72352, 73441);
  script_osvdb_id(116178, 116688, 116695, 116696, 116697, 117690, 117691, 117693, 117835, 117836, 123602);

  script_name(english:"Debian DLA-221-1 : tiff security update");
  script_summary(english:"Checks dpkg output for the updated packages.");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Debian host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Several vulnerabilities have been discovered in the LibTIFF library
and utilities for the Tag Image File Format. These could lead to a
denial of service, information disclosure or privilege escalation.

CVE-2014-8128

William Robinet discovered that out-of-bounds writes are triggered in
several of the LibTIFF utilities when processing crafted TIFF files.
Other applications using LibTIFF are also likely to be affected in the
same way.

CVE-2014-8129

William Robinet discovered that out-of-bounds reads and writes are
triggered in tiff2pdf when processing crafted TIFF files. Other
applications using LibTIFF are also likely to be affected in the same
way.

CVE-2014-9330

Paris Zoumpouloglou discovered that out-of-bounds reads and writes are
triggered in bmp2tiff when processing crafted BMP files.

CVE-2014-9655

Michal Zalewski discovered that out-of-bounds reads and writes are
triggered in LibTIFF when processing crafted TIFF files.

For the oldoldstable distribution (squeeze), these problems have been
fixed in version 3.9.4-5+squeeze12.

For the oldstable distribution (wheezy), these problems will be fixed
soon.

The stable distribution (jessie) was not affected by these problems as
they were fixed before release.

NOTE: Tenable Network Security has extracted the preceding description
block directly from the DLA security advisory. Tenable has attempted
to automatically clean and format it as much as possible without
introducing additional issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://lists.debian.org/debian-lts-announce/2015/05/msg00005.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://packages.debian.org/source/squeeze-lts/tiff"
  );
  script_set_attribute(attribute:"solution", value:"Upgrade the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:X/RL:O/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libtiff-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libtiff-opengl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libtiff-tools");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libtiff4");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libtiff4-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libtiffxx0c2");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:6.0");

  script_set_attribute(attribute:"patch_publication_date", value:"2015/05/15");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/05/18");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2015-2016 Tenable Network Security, Inc.");
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
if (deb_check(release:"6.0", prefix:"libtiff-doc", reference:"3.9.4-5+squeeze12")) flag++;
if (deb_check(release:"6.0", prefix:"libtiff-opengl", reference:"3.9.4-5+squeeze12")) flag++;
if (deb_check(release:"6.0", prefix:"libtiff-tools", reference:"3.9.4-5+squeeze12")) flag++;
if (deb_check(release:"6.0", prefix:"libtiff4", reference:"3.9.4-5+squeeze12")) flag++;
if (deb_check(release:"6.0", prefix:"libtiff4-dev", reference:"3.9.4-5+squeeze12")) flag++;
if (deb_check(release:"6.0", prefix:"libtiffxx0c2", reference:"3.9.4-5+squeeze12")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:deb_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
