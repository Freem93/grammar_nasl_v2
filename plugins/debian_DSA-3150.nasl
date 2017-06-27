#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Debian Security Advisory DSA-3150. The text 
# itself is copyright (C) Software in the Public Interest, Inc.
#

include("compat.inc");

if (description)
{
  script_id(81130);
  script_version("$Revision: 1.2 $");
  script_cvs_date("$Date: 2015/02/16 15:48:49 $");

  script_cve_id("CVE-2014-9626", "CVE-2014-9627", "CVE-2014-9628", "CVE-2014-9629", "CVE-2014-9630");
  script_bugtraq_id(72252);
  script_xref(name:"DSA", value:"3150");

  script_name(english:"Debian DSA-3150-1 : vlc - security update");
  script_summary(english:"Checks dpkg output for the updated package");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Debian host is missing a security-related update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Fabian Yamaguchi discovered multiple vulnerabilities in VLC, a
multimedia player and streamer :

  - CVE-2014-9626
    The MP4 demuxer, when parsing string boxes, did not
    properly check the length of the box, leading to a
    possible integer underflow when using this length value
    in a call to memcpy(). This could allow remote attackers
    to cause a denial of service (crash) or arbitrary code
    execution via crafted MP4 files.

  - CVE-2014-9627
    The MP4 demuxer, when parsing string boxes, did not
    properly check that the conversion of the box length
    from 64bit integer to 32bit integer on 32bit platforms
    did not cause a truncation, leading to a possible buffer
    overflow. This could allow remote attackers to cause a
    denial of service (crash) or arbitrary code execution
    via crafted MP4 files.

  - CVE-2014-9628
    The MP4 demuxer, when parsing string boxes, did not
    properly check the length of the box, leading to a
    possible buffer overflow. This could allow remote
    attackers to cause a denial of service (crash) or
    arbitrary code execution via crafted MP4 files.

  - CVE-2014-9629
    The Dirac and Schroedinger encoders did not properly
    check for an integer overflow on 32bit platforms,
    leading to a possible buffer overflow. This could allow
    remote attackers to cause a denial of service (crash) or
    arbitrary code execution."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2014-9626"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2014-9627"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2014-9628"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2014-9629"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://packages.debian.org/source/wheezy/vlc"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.debian.org/security/2015/dsa-3150"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"Upgrade the vlc packages.

For the stable distribution (wheezy), these problems have been fixed
in version 2.0.3-5+deb7u2.

For the upcoming stable distribution (jessie), these problems have
been fixed in version 2.2.0~rc2-2."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:vlc");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:7.0");

  script_set_attribute(attribute:"patch_publication_date", value:"2015/02/02");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/02/03");
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
if (deb_check(release:"7.0", prefix:"libvlc-dev", reference:"2.0.3-5+deb7u2")) flag++;
if (deb_check(release:"7.0", prefix:"libvlc5", reference:"2.0.3-5+deb7u2")) flag++;
if (deb_check(release:"7.0", prefix:"libvlccore-dev", reference:"2.0.3-5+deb7u2")) flag++;
if (deb_check(release:"7.0", prefix:"libvlccore5", reference:"2.0.3-5+deb7u2")) flag++;
if (deb_check(release:"7.0", prefix:"vlc", reference:"2.0.3-5+deb7u2")) flag++;
if (deb_check(release:"7.0", prefix:"vlc-data", reference:"2.0.3-5+deb7u2")) flag++;
if (deb_check(release:"7.0", prefix:"vlc-dbg", reference:"2.0.3-5+deb7u2")) flag++;
if (deb_check(release:"7.0", prefix:"vlc-nox", reference:"2.0.3-5+deb7u2")) flag++;
if (deb_check(release:"7.0", prefix:"vlc-plugin-fluidsynth", reference:"2.0.3-5+deb7u2")) flag++;
if (deb_check(release:"7.0", prefix:"vlc-plugin-jack", reference:"2.0.3-5+deb7u2")) flag++;
if (deb_check(release:"7.0", prefix:"vlc-plugin-notify", reference:"2.0.3-5+deb7u2")) flag++;
if (deb_check(release:"7.0", prefix:"vlc-plugin-pulse", reference:"2.0.3-5+deb7u2")) flag++;
if (deb_check(release:"7.0", prefix:"vlc-plugin-sdl", reference:"2.0.3-5+deb7u2")) flag++;
if (deb_check(release:"7.0", prefix:"vlc-plugin-svg", reference:"2.0.3-5+deb7u2")) flag++;
if (deb_check(release:"7.0", prefix:"vlc-plugin-zvbi", reference:"2.0.3-5+deb7u2")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:deb_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
