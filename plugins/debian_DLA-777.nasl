#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Debian Security Advisory DLA-777-1. The text
# itself is copyright (C) Software in the Public Interest, Inc.
#

include("compat.inc");

if (description)
{
  script_id(96272);
  script_version("$Revision: 3.1 $");
  script_cvs_date("$Date: 2017/01/04 15:13:58 $");

  script_name(english:"Debian DLA-777-1 : libvncserver security update");
  script_summary(english:"Checks dpkg output for the updated packages.");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Debian host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"It was discovered that there were two vulnerabilities in libvncserver,
a library to create/embed a VNC server :

  - CVE-2016-9941: Fix a heap-based buffer overflow that
    allows remote servers to cause a denial of service via a
    crafted FramebufferUpdate message containing a
    subrectangle outside of the drawing area.

  - CVE-2016-9942: Fix a heap-based buffer overflow that
    allow remote servers to cause a denial of service via a
    crafted FramebufferUpdate message with the 'Ultra' type
    tile such that the LZO decompressed payload exceeds the
    size of the tile dimensions.

For Debian 7 'Wheezy', these issues have been fixed in libvncserver
version 0.9.9+dfsg-1+deb7u2.

We recommend that you upgrade your libvncserver packages.

NOTE: Tenable Network Security has extracted the preceding description
block directly from the DLA security advisory. Tenable has attempted
to automatically clean and format it as much as possible without
introducing additional issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://lists.debian.org/debian-lts-announce/2017/01/msg00005.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://packages.debian.org/source/wheezy/libvncserver"
  );
  script_set_attribute(attribute:"solution", value:"Upgrade the affected packages.");
  script_set_attribute(attribute:"risk_factor", value:"High");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libvncserver-config");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libvncserver-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libvncserver0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libvncserver0-dbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linuxvnc");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:7.0");

  script_set_attribute(attribute:"patch_publication_date", value:"2017/01/03");
  script_set_attribute(attribute:"plugin_publication_date", value:"2017/01/04");
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
if (deb_check(release:"7.0", prefix:"libvncserver-config", reference:"0.9.9+dfsg-1+deb7u2")) flag++;
if (deb_check(release:"7.0", prefix:"libvncserver-dev", reference:"0.9.9+dfsg-1+deb7u2")) flag++;
if (deb_check(release:"7.0", prefix:"libvncserver0", reference:"0.9.9+dfsg-1+deb7u2")) flag++;
if (deb_check(release:"7.0", prefix:"libvncserver0-dbg", reference:"0.9.9+dfsg-1+deb7u2")) flag++;
if (deb_check(release:"7.0", prefix:"linuxvnc", reference:"0.9.9+dfsg-1+deb7u2")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:deb_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
