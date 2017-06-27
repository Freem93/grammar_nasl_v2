#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Debian Security Advisory DLA-902-1. The text
# itself is copyright (C) Software in the Public Interest, Inc.
#

include("compat.inc");

if (description)
{
  script_id(99443);
  script_version("$Revision: 3.1 $");
  script_cvs_date("$Date: 2017/04/19 13:27:09 $");

  script_cve_id("CVE-2017-7606", "CVE-2017-7619");
  script_osvdb_id(155098, 155176);

  script_name(english:"Debian DLA-902-1 : imagemagick security update");
  script_summary(english:"Checks dpkg output for the updated packages.");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Debian host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Two security vulnerabilities were discovered in imagemagick that allow
remote attackers to cause a denial of service (application crash and
infinite loop) or possibly other unspecified impact via a crafted
image.

For Debian 7 'Wheezy', these problems have been fixed in version
8:6.7.7.10-5+deb7u13.

We recommend that you upgrade your imagemagick packages.

NOTE: Tenable Network Security has extracted the preceding description
block directly from the DLA security advisory. Tenable has attempted
to automatically clean and format it as much as possible without
introducing additional issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://lists.debian.org/debian-lts-announce/2017/04/msg00020.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://packages.debian.org/source/wheezy/imagemagick"
  );
  script_set_attribute(attribute:"solution", value:"Upgrade the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:imagemagick");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:imagemagick-common");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:imagemagick-dbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:imagemagick-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libmagick++-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libmagick++5");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libmagickcore-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libmagickcore5");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libmagickcore5-extra");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libmagickwand-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libmagickwand5");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:perlmagick");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:7.0");

  script_set_attribute(attribute:"patch_publication_date", value:"2017/04/18");
  script_set_attribute(attribute:"plugin_publication_date", value:"2017/04/19");
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
if (deb_check(release:"7.0", prefix:"imagemagick", reference:"8:6.7.7.10-5+deb7u13")) flag++;
if (deb_check(release:"7.0", prefix:"imagemagick-common", reference:"8:6.7.7.10-5+deb7u13")) flag++;
if (deb_check(release:"7.0", prefix:"imagemagick-dbg", reference:"8:6.7.7.10-5+deb7u13")) flag++;
if (deb_check(release:"7.0", prefix:"imagemagick-doc", reference:"8:6.7.7.10-5+deb7u13")) flag++;
if (deb_check(release:"7.0", prefix:"libmagick++-dev", reference:"8:6.7.7.10-5+deb7u13")) flag++;
if (deb_check(release:"7.0", prefix:"libmagick++5", reference:"8:6.7.7.10-5+deb7u13")) flag++;
if (deb_check(release:"7.0", prefix:"libmagickcore-dev", reference:"8:6.7.7.10-5+deb7u13")) flag++;
if (deb_check(release:"7.0", prefix:"libmagickcore5", reference:"8:6.7.7.10-5+deb7u13")) flag++;
if (deb_check(release:"7.0", prefix:"libmagickcore5-extra", reference:"8:6.7.7.10-5+deb7u13")) flag++;
if (deb_check(release:"7.0", prefix:"libmagickwand-dev", reference:"8:6.7.7.10-5+deb7u13")) flag++;
if (deb_check(release:"7.0", prefix:"libmagickwand5", reference:"8:6.7.7.10-5+deb7u13")) flag++;
if (deb_check(release:"7.0", prefix:"perlmagick", reference:"8:6.7.7.10-5+deb7u13")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:deb_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
