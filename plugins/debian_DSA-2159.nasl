#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Debian Security Advisory DSA-2159. The text 
# itself is copyright (C) Software in the Public Interest, Inc.
#

include("compat.inc");

if (description)
{
  script_id(51946);
  script_version("$Revision: 1.9 $");
  script_cvs_date("$Date: 2015/02/16 15:31:54 $");

  script_cve_id("CVE-2011-0531");
  script_bugtraq_id(46060);
  script_osvdb_id(70698);
  script_xref(name:"DSA", value:"2159");

  script_name(english:"Debian DSA-2159-1 : vlc - missing input sanitising");
  script_summary(english:"Checks dpkg output for the updated package");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Debian host is missing a security-related update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Dan Rosenberg discovered that insufficient input validation in VLC's
processing of Matroska/WebM containers could lead to the execution of
arbitrary code."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://packages.debian.org/source/squeeze/vlc"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.debian.org/security/2011/dsa-2159"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"Upgrade the vlc packages.

For the stable distribution (squeeze), this problem has been fixed in
version 1.1.3-1squeeze3.

The version of vlc in the oldstable distribution (lenny) is affected
by further issues and will be addressed in a followup DSA."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_core", value:"true");
  script_set_attribute(attribute:"metasploit_name", value:'VideoLAN VLC MKV Memory Corruption');
  script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:vlc");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:6.0");

  script_set_attribute(attribute:"patch_publication_date", value:"2011/02/10");
  script_set_attribute(attribute:"plugin_publication_date", value:"2011/02/11");
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
if (deb_check(release:"6.0", prefix:"libvlc-dev", reference:"1.1.3-1squeeze3")) flag++;
if (deb_check(release:"6.0", prefix:"libvlc5", reference:"1.1.3-1squeeze3")) flag++;
if (deb_check(release:"6.0", prefix:"libvlccore-dev", reference:"1.1.3-1squeeze3")) flag++;
if (deb_check(release:"6.0", prefix:"libvlccore4", reference:"1.1.3-1squeeze3")) flag++;
if (deb_check(release:"6.0", prefix:"mozilla-plugin-vlc", reference:"1.1.3-1squeeze3")) flag++;
if (deb_check(release:"6.0", prefix:"vlc", reference:"1.1.3-1squeeze3")) flag++;
if (deb_check(release:"6.0", prefix:"vlc-data", reference:"1.1.3-1squeeze3")) flag++;
if (deb_check(release:"6.0", prefix:"vlc-dbg", reference:"1.1.3-1squeeze3")) flag++;
if (deb_check(release:"6.0", prefix:"vlc-nox", reference:"1.1.3-1squeeze3")) flag++;
if (deb_check(release:"6.0", prefix:"vlc-plugin-fluidsynth", reference:"1.1.3-1squeeze3")) flag++;
if (deb_check(release:"6.0", prefix:"vlc-plugin-ggi", reference:"1.1.3-1squeeze3")) flag++;
if (deb_check(release:"6.0", prefix:"vlc-plugin-jack", reference:"1.1.3-1squeeze3")) flag++;
if (deb_check(release:"6.0", prefix:"vlc-plugin-notify", reference:"1.1.3-1squeeze3")) flag++;
if (deb_check(release:"6.0", prefix:"vlc-plugin-pulse", reference:"1.1.3-1squeeze3")) flag++;
if (deb_check(release:"6.0", prefix:"vlc-plugin-sdl", reference:"1.1.3-1squeeze3")) flag++;
if (deb_check(release:"6.0", prefix:"vlc-plugin-svg", reference:"1.1.3-1squeeze3")) flag++;
if (deb_check(release:"6.0", prefix:"vlc-plugin-svgalib", reference:"1.1.3-1squeeze3")) flag++;
if (deb_check(release:"6.0", prefix:"vlc-plugin-zvbi", reference:"1.1.3-1squeeze3")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:deb_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
