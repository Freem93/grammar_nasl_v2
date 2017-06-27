#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Debian Security Advisory DLA-450-1. The text
# itself is copyright (C) Software in the Public Interest, Inc.
#

include("compat.inc");

if (description)
{
  script_id(90807);
  script_version("$Revision: 2.3 $");
  script_cvs_date("$Date: 2016/12/06 20:03:51 $");

  script_cve_id("CVE-2015-7552", "CVE-2015-7674");
  script_osvdb_id(128371, 133603);

  script_name(english:"Debian DLA-450-1 : gdk-pixbuf security update");
  script_summary(english:"Checks dpkg output for the updated packages.");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Debian host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"A heap-based buffer overflow has been discovered in gdk-pixbuf, a
library for image loading and saving facilities, fast scaling and
compositing of pixbufs, that allows remote attackers to cause a denial
of service or possibly execute arbitrary code via a crafted BMP file.

This update also fixes an incomplete patch for CVE-2015-7674.

CVE-2015-7552 Heap-based buffer overflow in the gdk_pixbuf_flip
function in gdk-pixbuf-scale.c in gdk-pixbuf allows remote attackers
to cause a denial of service or possibly execute arbitrary code via a
crafted BMP file.

CVE-2015-7674 Integer overflow in the pixops_scale_nearest function in
pixops/pixops.c in gdk-pixbuf before 2.32.1 allows remote attackers to
cause a denial of service (application crash) and possibly execute
arbitrary code via a crafted GIF image file, which triggers a
heap-based buffer overflow.

For Debian 7 'Wheezy', these problems have been fixed in version
2.26.1-1+deb7u4.

We recommend that you upgrade your gdk-pixbuf packages.

NOTE: Tenable Network Security has extracted the preceding description
block directly from the DLA security advisory. Tenable has attempted
to automatically clean and format it as much as possible without
introducing additional issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://lists.debian.org/debian-lts-announce/2016/04/msg00004.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://packages.debian.org/source/wheezy/gdk-pixbuf"
  );
  script_set_attribute(attribute:"solution", value:"Upgrade the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:gir1.2-gdkpixbuf-2.0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libgdk-pixbuf2.0-0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libgdk-pixbuf2.0-common");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libgdk-pixbuf2.0-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libgdk-pixbuf2.0-doc");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:7.0");

  script_set_attribute(attribute:"patch_publication_date", value:"2016/04/30");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/05/02");
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
if (deb_check(release:"7.0", prefix:"gir1.2-gdkpixbuf-2.0", reference:"2.26.1-1+deb7u4")) flag++;
if (deb_check(release:"7.0", prefix:"libgdk-pixbuf2.0-0", reference:"2.26.1-1+deb7u4")) flag++;
if (deb_check(release:"7.0", prefix:"libgdk-pixbuf2.0-common", reference:"2.26.1-1+deb7u4")) flag++;
if (deb_check(release:"7.0", prefix:"libgdk-pixbuf2.0-dev", reference:"2.26.1-1+deb7u4")) flag++;
if (deb_check(release:"7.0", prefix:"libgdk-pixbuf2.0-doc", reference:"2.26.1-1+deb7u4")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:deb_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
