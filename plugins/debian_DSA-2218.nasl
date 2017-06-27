#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Debian Security Advisory DSA-2218. The text 
# itself is copyright (C) Software in the Public Interest, Inc.
#

include("compat.inc");

if (description)
{
  script_id(53393);
  script_version("$Revision: 1.8 $");
  script_cvs_date("$Date: 2015/02/16 15:31:55 $");

  script_cve_id("CVE-2011-1684");
  script_bugtraq_id(47293);
  script_osvdb_id(71705);
  script_xref(name:"DSA", value:"2218");

  script_name(english:"Debian DSA-2218-1 : vlc - heap-based buffer overflow");
  script_summary(english:"Checks dpkg output for the updated package");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Debian host is missing a security-related update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Aliz Hammond discovered that the MP4 decoder plugin of VLC, a
multimedia player and streamer, is vulnerable to a heap-based buffer
overflow. This has been introduced by a wrong data type being used for
a size calculation. An attacker could use this flaw to trick a victim
into opening a specially crafted MP4 file and possibly execute
arbitrary code or crash the media player.

The oldstable distribution (lenny) is not affected by this problem."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://packages.debian.org/source/squeeze/vlc"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.debian.org/security/2011/dsa-2218"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"Upgrade the vlc packages.

For the stable distribution (squeeze), this problem has been fixed in
version 1.1.3-1squeeze5."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:vlc");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:6.0");

  script_set_attribute(attribute:"patch_publication_date", value:"2011/04/12");
  script_set_attribute(attribute:"plugin_publication_date", value:"2011/04/13");
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
if (deb_check(release:"6.0", prefix:"libvlc-dev", reference:"1.1.3-1squeeze5")) flag++;
if (deb_check(release:"6.0", prefix:"libvlc5", reference:"1.1.3-1squeeze5")) flag++;
if (deb_check(release:"6.0", prefix:"libvlccore-dev", reference:"1.1.3-1squeeze5")) flag++;
if (deb_check(release:"6.0", prefix:"libvlccore4", reference:"1.1.3-1squeeze5")) flag++;
if (deb_check(release:"6.0", prefix:"mozilla-plugin-vlc", reference:"1.1.3-1squeeze5")) flag++;
if (deb_check(release:"6.0", prefix:"vlc", reference:"1.1.3-1squeeze5")) flag++;
if (deb_check(release:"6.0", prefix:"vlc-data", reference:"1.1.3-1squeeze5")) flag++;
if (deb_check(release:"6.0", prefix:"vlc-dbg", reference:"1.1.3-1squeeze5")) flag++;
if (deb_check(release:"6.0", prefix:"vlc-nox", reference:"1.1.3-1squeeze5")) flag++;
if (deb_check(release:"6.0", prefix:"vlc-plugin-fluidsynth", reference:"1.1.3-1squeeze5")) flag++;
if (deb_check(release:"6.0", prefix:"vlc-plugin-ggi", reference:"1.1.3-1squeeze5")) flag++;
if (deb_check(release:"6.0", prefix:"vlc-plugin-jack", reference:"1.1.3-1squeeze5")) flag++;
if (deb_check(release:"6.0", prefix:"vlc-plugin-notify", reference:"1.1.3-1squeeze5")) flag++;
if (deb_check(release:"6.0", prefix:"vlc-plugin-pulse", reference:"1.1.3-1squeeze5")) flag++;
if (deb_check(release:"6.0", prefix:"vlc-plugin-sdl", reference:"1.1.3-1squeeze5")) flag++;
if (deb_check(release:"6.0", prefix:"vlc-plugin-svg", reference:"1.1.3-1squeeze5")) flag++;
if (deb_check(release:"6.0", prefix:"vlc-plugin-svgalib", reference:"1.1.3-1squeeze5")) flag++;
if (deb_check(release:"6.0", prefix:"vlc-plugin-zvbi", reference:"1.1.3-1squeeze5")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:deb_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
