#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Debian Security Advisory DSA-1332. The text 
# itself is copyright (C) Software in the Public Interest, Inc.
#

include("compat.inc");

if (description)
{
  script_id(25695);
  script_version("$Revision: 1.14 $");
  script_cvs_date("$Date: 2014/05/03 11:14:58 $");

  script_cve_id("CVE-2007-3316", "CVE-2007-3467", "CVE-2007-3468");
  script_osvdb_id(37379, 37380, 37381, 37382, 38992, 42189);
  script_xref(name:"DSA", value:"1332");

  script_name(english:"Debian DSA-1332-1 : vlc - several vulnerabilities");
  script_summary(english:"Checks dpkg output for the updated package");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Debian host is missing a security-related update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Several remote vulnerabilities have been discovered in the VideoLan
multimedia player and streamer, which may lead to the execution of
arbitrary code. The Common Vulnerabilities and Exposures project
identifies the following problems :

  - CVE-2007-3316
    David Thiel discovered that several format string
    vulnerabilities may lead to the execution of arbitrary
    code.

  - CVE-2007-3467
    David Thiel discovered an integer overflow in the WAV
    processing code.

This update also fixes several crashes, which can be triggered through
malformed media files."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://bugs.debian.org/cgi-bin/bugreport.cgi?bug=429726"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2007-3316"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2007-3467"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.debian.org/security/2007/dsa-1332"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"Upgrade the vlc packages.

For the oldstable distribution (sarge) these problems have been fixed
in version 0.8.1.svn20050314-1sarge3. Packages for the powerpc
architecture are not yet available. They will be provided later.

For the stable distribution (etch) these problems have been fixed in
version 0.8.6-svn20061012.debian-5etch1."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_core", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:vlc");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:3.1");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:4.0");

  script_set_attribute(attribute:"patch_publication_date", value:"2007/07/09");
  script_set_attribute(attribute:"plugin_publication_date", value:"2007/07/11");
  script_set_attribute(attribute:"vuln_publication_date", value:"2007/06/20");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2007-2014 Tenable Network Security, Inc.");
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
if (deb_check(release:"3.1", prefix:"gnome-vlc", reference:"0.8.1.svn20050314-1sarge3")) flag++;
if (deb_check(release:"3.1", prefix:"gvlc", reference:"0.8.1.svn20050314-1sarge3")) flag++;
if (deb_check(release:"3.1", prefix:"kvlc", reference:"0.8.1.svn20050314-1sarge3")) flag++;
if (deb_check(release:"3.1", prefix:"libvlc0-dev", reference:"0.8.1.svn20050314-1sarge3")) flag++;
if (deb_check(release:"3.1", prefix:"mozilla-plugin-vlc", reference:"0.8.1.svn20050314-1sarge3")) flag++;
if (deb_check(release:"3.1", prefix:"qvlc", reference:"0.8.1.svn20050314-1sarge3")) flag++;
if (deb_check(release:"3.1", prefix:"vlc", reference:"0.8.1.svn20050314-1sarge3")) flag++;
if (deb_check(release:"3.1", prefix:"vlc-alsa", reference:"0.8.1.svn20050314-1sarge3")) flag++;
if (deb_check(release:"3.1", prefix:"vlc-esd", reference:"0.8.1.svn20050314-1sarge3")) flag++;
if (deb_check(release:"3.1", prefix:"vlc-ggi", reference:"0.8.1.svn20050314-1sarge3")) flag++;
if (deb_check(release:"3.1", prefix:"vlc-glide", reference:"0.8.1.svn20050314-1sarge3")) flag++;
if (deb_check(release:"3.1", prefix:"vlc-gnome", reference:"0.8.1.svn20050314-1sarge3")) flag++;
if (deb_check(release:"3.1", prefix:"vlc-gtk", reference:"0.8.1.svn20050314-1sarge3")) flag++;
if (deb_check(release:"3.1", prefix:"vlc-plugin-alsa", reference:"0.8.1.svn20050314-1sarge3")) flag++;
if (deb_check(release:"3.1", prefix:"vlc-plugin-arts", reference:"0.8.1.svn20050314-1sarge3")) flag++;
if (deb_check(release:"3.1", prefix:"vlc-plugin-esd", reference:"0.8.1.svn20050314-1sarge3")) flag++;
if (deb_check(release:"3.1", prefix:"vlc-plugin-ggi", reference:"0.8.1.svn20050314-1sarge3")) flag++;
if (deb_check(release:"3.1", prefix:"vlc-plugin-glide", reference:"0.8.1.svn20050314-1sarge3")) flag++;
if (deb_check(release:"3.1", prefix:"vlc-plugin-sdl", reference:"0.8.1.svn20050314-1sarge3")) flag++;
if (deb_check(release:"3.1", prefix:"vlc-plugin-svgalib", reference:"0.8.1.svn20050314-1sarge3")) flag++;
if (deb_check(release:"3.1", prefix:"vlc-qt", reference:"0.8.1.svn20050314-1sarge3")) flag++;
if (deb_check(release:"3.1", prefix:"vlc-sdl", reference:"0.8.1.svn20050314-1sarge3")) flag++;
if (deb_check(release:"3.1", prefix:"wxvlc", reference:"0.8.1.svn20050314-1sarge3")) flag++;
if (deb_check(release:"4.0", prefix:"libvlc0", reference:"0.8.6-svn20061012.debian-5etch1")) flag++;
if (deb_check(release:"4.0", prefix:"libvlc0-dev", reference:"0.8.6-svn20061012.debian-5etch1")) flag++;
if (deb_check(release:"4.0", prefix:"mozilla-plugin-vlc", reference:"0.8.6-svn20061012.debian-5etch1")) flag++;
if (deb_check(release:"4.0", prefix:"vlc", reference:"0.8.6-svn20061012.debian-5etch1")) flag++;
if (deb_check(release:"4.0", prefix:"vlc-nox", reference:"0.8.6-svn20061012.debian-5etch1")) flag++;
if (deb_check(release:"4.0", prefix:"vlc-plugin-alsa", reference:"0.8.6-svn20061012.debian-5etch1")) flag++;
if (deb_check(release:"4.0", prefix:"vlc-plugin-arts", reference:"0.8.6-svn20061012.debian-5etch1")) flag++;
if (deb_check(release:"4.0", prefix:"vlc-plugin-esd", reference:"0.8.6-svn20061012.debian-5etch1")) flag++;
if (deb_check(release:"4.0", prefix:"vlc-plugin-ggi", reference:"0.8.6-svn20061012.debian-5etch1")) flag++;
if (deb_check(release:"4.0", prefix:"vlc-plugin-glide", reference:"0.8.6-svn20061012.debian-5etch1")) flag++;
if (deb_check(release:"4.0", prefix:"vlc-plugin-sdl", reference:"0.8.6-svn20061012.debian-5etch1")) flag++;
if (deb_check(release:"4.0", prefix:"vlc-plugin-svgalib", reference:"0.8.6-svn20061012.debian-5etch1")) flag++;
if (deb_check(release:"4.0", prefix:"wxvlc", reference:"0.8.6-svn20061012.debian-5etch1")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:deb_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
