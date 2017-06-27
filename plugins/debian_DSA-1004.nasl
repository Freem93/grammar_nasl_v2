#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Debian Security Advisory DSA-1004. The text 
# itself is copyright (C) Software in the Public Interest, Inc.
#

include("compat.inc");

if (description)
{
  script_id(22546);
  script_version("$Revision: 1.13 $");
  script_cvs_date("$Date: 2013/05/17 23:36:51 $");

  script_cve_id("CVE-2005-4048");
  script_osvdb_id(21458);
  script_xref(name:"DSA", value:"1004");

  script_name(english:"Debian DSA-1004-1 : vlc - buffer overflow");
  script_summary(english:"Checks dpkg output for the updated package");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Debian host is missing a security-related update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Simon Kilvington discovered that specially crafted PNG images can
trigger a heap overflow in libavcodec, the multimedia library of
ffmpeg, which may lead to the execution of arbitrary code. The vlc
media player links statically against libavcodec."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://bugs.debian.org/cgi-bin/bugreport.cgi?bug=342208"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.debian.org/security/2006/dsa-1004"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"Upgrade the vlc package.

The old stable distribution (woody) isn't affected by this problem.

For the stable distribution (sarge) this problem has been fixed in
version 0.8.1.svn20050314-1sarge1."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:vlc");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:3.1");

  script_set_attribute(attribute:"patch_publication_date", value:"2006/03/16");
  script_set_attribute(attribute:"plugin_publication_date", value:"2006/10/14");
  script_set_attribute(attribute:"vuln_publication_date", value:"2005/11/30");
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
if (deb_check(release:"3.1", prefix:"gnome-vlc", reference:"0.8.1.svn20050314-1sarge1")) flag++;
if (deb_check(release:"3.1", prefix:"gvlc", reference:"0.8.1.svn20050314-1sarge1")) flag++;
if (deb_check(release:"3.1", prefix:"kvlc", reference:"0.8.1.svn20050314-1sarge1")) flag++;
if (deb_check(release:"3.1", prefix:"libvlc0-dev", reference:"0.8.1.svn20050314-1sarge1")) flag++;
if (deb_check(release:"3.1", prefix:"mozilla-plugin-vlc", reference:"0.8.1.svn20050314-1sarge1")) flag++;
if (deb_check(release:"3.1", prefix:"qvlc", reference:"0.8.1.svn20050314-1sarge1")) flag++;
if (deb_check(release:"3.1", prefix:"vlc", reference:"0.8.1.svn20050314-1sarge1")) flag++;
if (deb_check(release:"3.1", prefix:"vlc-alsa", reference:"0.8.1.svn20050314-1sarge1")) flag++;
if (deb_check(release:"3.1", prefix:"vlc-esd", reference:"0.8.1.svn20050314-1sarge1")) flag++;
if (deb_check(release:"3.1", prefix:"vlc-ggi", reference:"0.8.1.svn20050314-1sarge1")) flag++;
if (deb_check(release:"3.1", prefix:"vlc-glide", reference:"0.8.1.svn20050314-1sarge1")) flag++;
if (deb_check(release:"3.1", prefix:"vlc-gnome", reference:"0.8.1.svn20050314-1sarge1")) flag++;
if (deb_check(release:"3.1", prefix:"vlc-gtk", reference:"0.8.1.svn20050314-1sarge1")) flag++;
if (deb_check(release:"3.1", prefix:"vlc-plugin-alsa", reference:"0.8.1.svn20050314-1sarge1")) flag++;
if (deb_check(release:"3.1", prefix:"vlc-plugin-arts", reference:"0.8.1.svn20050314-1sarge1")) flag++;
if (deb_check(release:"3.1", prefix:"vlc-plugin-esd", reference:"0.8.1.svn20050314-1sarge1")) flag++;
if (deb_check(release:"3.1", prefix:"vlc-plugin-ggi", reference:"0.8.1.svn20050314-1sarge1")) flag++;
if (deb_check(release:"3.1", prefix:"vlc-plugin-glide", reference:"0.8.1.svn20050314-1sarge1")) flag++;
if (deb_check(release:"3.1", prefix:"vlc-plugin-sdl", reference:"0.8.1.svn20050314-1sarge1")) flag++;
if (deb_check(release:"3.1", prefix:"vlc-plugin-svgalib", reference:"0.8.1.svn20050314-1sarge1")) flag++;
if (deb_check(release:"3.1", prefix:"vlc-qt", reference:"0.8.1.svn20050314-1sarge1")) flag++;
if (deb_check(release:"3.1", prefix:"vlc-sdl", reference:"0.8.1.svn20050314-1sarge1")) flag++;
if (deb_check(release:"3.1", prefix:"wxvlc", reference:"0.8.1.svn20050314-1sarge1")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:deb_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
