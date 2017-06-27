#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Debian Security Advisory DSA-2043. The text 
# itself is copyright (C) Software in the Public Interest, Inc.
#

include("compat.inc");

if (description)
{
  script_id(46314);
  script_version("$Revision: 1.6 $");
  script_cvs_date("$Date: 2013/11/21 11:45:12 $");

  script_osvdb_id(56605);
  script_xref(name:"DSA", value:"2043");

  script_name(english:"Debian DSA-2043-1 : vlc - integer overflow");
  script_summary(english:"Checks dpkg output for the updated package");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Debian host is missing a security-related update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"tixxDZ (DZCORE labs) discovered a vulnerability in vlc, the multimedia
player and streamer. Missing data validation in vlc's real data
transport (RDT) implementation enable an integer underflow and
consequently an unbounded buffer operation. A maliciously crafted
stream could thus enable an attacker to execute arbitrary code.

No Common Vulnerabilities and Exposures project identifier is
available for this issue."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.debian.org/security/2010/dsa-2043"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"Upgrade the vlc packages.

For the stable distribution (lenny), this problem has been fixed in
version 0.8.6.h-4+lenny2.3."
  );
  script_set_attribute(attribute:"risk_factor", value:"High");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:vlc");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:5.0");

  script_set_attribute(attribute:"patch_publication_date", value:"2010/05/11");
  script_set_attribute(attribute:"plugin_publication_date", value:"2010/05/12");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2010-2013 Tenable Network Security, Inc.");
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
if (deb_check(release:"5.0", prefix:"libvlc0", reference:"0.8.6.h-4+lenny2.3")) flag++;
if (deb_check(release:"5.0", prefix:"libvlc0-dev", reference:"0.8.6.h-4+lenny2.3")) flag++;
if (deb_check(release:"5.0", prefix:"mozilla-plugin-vlc", reference:"0.8.6.h-4+lenny2.3")) flag++;
if (deb_check(release:"5.0", prefix:"vlc", reference:"0.8.6.h-4+lenny2.3")) flag++;
if (deb_check(release:"5.0", prefix:"vlc-nox", reference:"0.8.6.h-4+lenny2.3")) flag++;
if (deb_check(release:"5.0", prefix:"vlc-plugin-arts", reference:"0.8.6.h-4+lenny2.3")) flag++;
if (deb_check(release:"5.0", prefix:"vlc-plugin-esd", reference:"0.8.6.h-4+lenny2.3")) flag++;
if (deb_check(release:"5.0", prefix:"vlc-plugin-ggi", reference:"0.8.6.h-4+lenny2.3")) flag++;
if (deb_check(release:"5.0", prefix:"vlc-plugin-glide", reference:"0.8.6.h-4+lenny2.3")) flag++;
if (deb_check(release:"5.0", prefix:"vlc-plugin-jack", reference:"0.8.6.h-4+lenny2.3")) flag++;
if (deb_check(release:"5.0", prefix:"vlc-plugin-sdl", reference:"0.8.6.h-4+lenny2.3")) flag++;
if (deb_check(release:"5.0", prefix:"vlc-plugin-svgalib", reference:"0.8.6.h-4+lenny2.3")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:deb_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
