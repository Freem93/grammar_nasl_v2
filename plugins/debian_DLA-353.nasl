#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Debian Security Advisory DLA-353-1. The text
# itself is copyright (C) Software in the Public Interest, Inc.
#

include("compat.inc");

if (description)
{
  script_id(87074);
  script_version("$Revision: 2.2 $");
  script_cvs_date("$Date: 2015/12/02 20:16:12 $");

  script_name(english:"Debian DLA-353-1 : imagemagick security update");
  script_summary(english:"Checks dpkg output for the updated packages.");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Debian host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Submitting specially crafted icons (.ico) or .pict images to
ImageMagick can trigger integer overflows that can lead to buffer
overflows and memory allocations issues. Depending on the case, this
can lead to a denial of service or possibly worse.

For Debian 6 Squeeze, those issues have been fixed in imagemagick
8:6.6.0.4-3+squeeze7. We recommend that you upgrade your packages.

NOTE: Tenable Network Security has extracted the preceding description
block directly from the DLA security advisory. Tenable has attempted
to automatically clean and format it as much as possible without
introducing additional issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://lists.debian.org/debian-lts-announce/2015/11/msg00014.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://packages.debian.org/source/squeeze-lts/imagemagick"
  );
  script_set_attribute(attribute:"solution", value:"Upgrade the affected packages.");
  script_set_attribute(attribute:"risk_factor", value:"High");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:imagemagick");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:imagemagick-dbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:imagemagick-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libmagick++-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libmagick++3");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libmagickcore-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libmagickcore3");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libmagickcore3-extra");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libmagickwand-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libmagickwand3");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:perlmagick");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:6.0");

  script_set_attribute(attribute:"patch_publication_date", value:"2015/11/27");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/11/30");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2015 Tenable Network Security, Inc.");
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
if (deb_check(release:"6.0", prefix:"imagemagick", reference:"8:6.6.0.4-3+squeeze7")) flag++;
if (deb_check(release:"6.0", prefix:"imagemagick-dbg", reference:"8:6.6.0.4-3+squeeze7")) flag++;
if (deb_check(release:"6.0", prefix:"imagemagick-doc", reference:"8:6.6.0.4-3+squeeze7")) flag++;
if (deb_check(release:"6.0", prefix:"libmagick++-dev", reference:"8:6.6.0.4-3+squeeze7")) flag++;
if (deb_check(release:"6.0", prefix:"libmagick++3", reference:"8:6.6.0.4-3+squeeze7")) flag++;
if (deb_check(release:"6.0", prefix:"libmagickcore-dev", reference:"8:6.6.0.4-3+squeeze7")) flag++;
if (deb_check(release:"6.0", prefix:"libmagickcore3", reference:"8:6.6.0.4-3+squeeze7")) flag++;
if (deb_check(release:"6.0", prefix:"libmagickcore3-extra", reference:"8:6.6.0.4-3+squeeze7")) flag++;
if (deb_check(release:"6.0", prefix:"libmagickwand-dev", reference:"8:6.6.0.4-3+squeeze7")) flag++;
if (deb_check(release:"6.0", prefix:"libmagickwand3", reference:"8:6.6.0.4-3+squeeze7")) flag++;
if (deb_check(release:"6.0", prefix:"perlmagick", reference:"8:6.6.0.4-3+squeeze7")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:deb_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
