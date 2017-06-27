#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Debian Security Advisory DSA-2211. The text 
# itself is copyright (C) Software in the Public Interest, Inc.
#

include("compat.inc");

if (description)
{
  script_id(53304);
  script_version("$Revision: 1.12 $");
  script_cvs_date("$Date: 2015/02/16 15:31:55 $");

  script_cve_id("CVE-2010-3275", "CVE-2010-3276");
  script_bugtraq_id(47012);
  script_osvdb_id(70698, 71277, 71278, 72905, 72906, 74733, 74734);
  script_xref(name:"DSA", value:"2211");

  script_name(english:"Debian DSA-2211-1 : vlc - missing input sanitising");
  script_summary(english:"Checks dpkg output for the updated package");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Debian host is missing a security-related update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Ricardo Narvaja discovered that missing input sanitising in VLC, a
multimedia player and streamer, could lead to the execution of
arbitrary code if a user is tricked into opening a malformed media
file.

This update also provides updated packages for oldstable (lenny) for
vulnerabilities, which have already been addressed in Debian stable
(squeeze), either during the freeze or in DSA-2159(CVE-2010-0522,
CVE-2010-1441, CVE-2010-1442 and CVE-2011-0531 )."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2010-0522"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2010-1441"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2010-1442"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2011-0531"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://packages.debian.org/source/squeeze/vlc"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.debian.org/security/2011/dsa-2211"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"Upgrade the vlc packages.

For the oldstable distribution (lenny), this problem has been fixed in
version 0.8.6.h-4+lenny3.

For the stable distribution (squeeze), this problem has been fixed in
version 1.1.3-1squeeze4."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_core", value:"true");
  script_set_attribute(attribute:"metasploit_name", value:'VLC AMV Dangling Pointer Vulnerability');
  script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");
  script_set_attribute(attribute:"exploit_framework_canvas", value:"true");
  script_set_attribute(attribute:"canvas_package", value:'White_Phosphorus');

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:vlc");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:5.0");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:6.0");

  script_set_attribute(attribute:"patch_publication_date", value:"2011/04/06");
  script_set_attribute(attribute:"plugin_publication_date", value:"2011/04/07");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2011-2015 Tenable Network Security, Inc.");
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
if (deb_check(release:"5.0", prefix:"vlc", reference:"0.8.6.h-4+lenny3")) flag++;
if (deb_check(release:"6.0", prefix:"libvlc-dev", reference:"1.1.3-1squeeze4")) flag++;
if (deb_check(release:"6.0", prefix:"libvlc5", reference:"1.1.3-1squeeze4")) flag++;
if (deb_check(release:"6.0", prefix:"libvlccore-dev", reference:"1.1.3-1squeeze4")) flag++;
if (deb_check(release:"6.0", prefix:"libvlccore4", reference:"1.1.3-1squeeze4")) flag++;
if (deb_check(release:"6.0", prefix:"mozilla-plugin-vlc", reference:"1.1.3-1squeeze4")) flag++;
if (deb_check(release:"6.0", prefix:"vlc", reference:"1.1.3-1squeeze4")) flag++;
if (deb_check(release:"6.0", prefix:"vlc-data", reference:"1.1.3-1squeeze4")) flag++;
if (deb_check(release:"6.0", prefix:"vlc-dbg", reference:"1.1.3-1squeeze4")) flag++;
if (deb_check(release:"6.0", prefix:"vlc-nox", reference:"1.1.3-1squeeze4")) flag++;
if (deb_check(release:"6.0", prefix:"vlc-plugin-fluidsynth", reference:"1.1.3-1squeeze4")) flag++;
if (deb_check(release:"6.0", prefix:"vlc-plugin-ggi", reference:"1.1.3-1squeeze4")) flag++;
if (deb_check(release:"6.0", prefix:"vlc-plugin-jack", reference:"1.1.3-1squeeze4")) flag++;
if (deb_check(release:"6.0", prefix:"vlc-plugin-notify", reference:"1.1.3-1squeeze4")) flag++;
if (deb_check(release:"6.0", prefix:"vlc-plugin-pulse", reference:"1.1.3-1squeeze4")) flag++;
if (deb_check(release:"6.0", prefix:"vlc-plugin-sdl", reference:"1.1.3-1squeeze4")) flag++;
if (deb_check(release:"6.0", prefix:"vlc-plugin-svg", reference:"1.1.3-1squeeze4")) flag++;
if (deb_check(release:"6.0", prefix:"vlc-plugin-svgalib", reference:"1.1.3-1squeeze4")) flag++;
if (deb_check(release:"6.0", prefix:"vlc-plugin-zvbi", reference:"1.1.3-1squeeze4")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:deb_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
